/*
 * FBVBS xAPIC/x2APIC Virtualization Model (Phase 1-7)
 *
 * Provides APIC mode detection, APIC access page configuration,
 * virtual interrupt delivery, timer virtualization, and EOI handling
 * for single-socket BSP operation.
 *
 * Design references:
 *   - Intel SDM Vol. 3C Chapter 29: APIC Virtualization
 *   - AMD APM Vol. 2 Section 15.29: AVIC
 *   - fbvbs-design.md Section 8.3 (interrupt delivery)
 *
 * PRODUCTION NOTE: This module provides model-level implementations.
 * Production deployment requires:
 *   - Real APIC base MSR reads (IA32_APIC_BASE)
 *   - MMIO trap handling for xAPIC register accesses
 *   - Posted interrupt descriptor (PID) allocation and management
 *   - Physical APIC page identity mapping in EPT
 */

#include <stdint.h>

#include "fbvbs_hypervisor.h"
#include "fbvbs_asm.h"

/* ================================================================
 * APIC mode constants
 * ================================================================ */

#define APIC_BASE_MSR           0x1BU
#define APIC_BASE_ENABLE        (1ULL << 11)
#define APIC_BASE_X2APIC_ENABLE (1ULL << 10)
#define APIC_BASE_BSP           (1ULL << 8)
#define APIC_DEFAULT_BASE       0xFEE00000ULL

/* xAPIC register offsets (MMIO from APIC_DEFAULT_BASE) */
#define APIC_REG_ID             0x020U
#define APIC_REG_VERSION        0x030U
#define APIC_REG_TPR            0x080U
#define APIC_REG_EOI            0x0B0U
#define APIC_REG_LDR            0x0D0U
#define APIC_REG_DFR            0x0E0U
#define APIC_REG_SVR            0x0F0U
#define APIC_REG_ISR_BASE       0x100U
#define APIC_REG_TMR_BASE       0x180U
#define APIC_REG_IRR_BASE       0x200U
#define APIC_REG_ESR            0x280U
#define APIC_REG_ICR_LO         0x300U
#define APIC_REG_ICR_HI         0x310U
#define APIC_REG_LVT_TIMER      0x320U
#define APIC_REG_TIMER_INIT     0x380U
#define APIC_REG_TIMER_CURRENT  0x390U
#define APIC_REG_TIMER_DIVIDE   0x3E0U

/* VMX secondary proc-based control bits for APIC virtualization */
#define PROC2_VIRTUALIZE_APIC_ACCESSES  (1U << 0)
#define PROC2_VIRTUALIZE_X2APIC_MODE    (1U << 4)
#define PROC2_VIRTUAL_INT_DELIVERY      (1U << 9)
#define PROC2_APIC_REGISTER_VIRT        (1U << 8)

/* Pin-based control bits for posted interrupts */
#define PIN_POSTED_INTERRUPTS           (1U << 7)

/* APIC timer modes */
#define APIC_TIMER_MODE_ONESHOT     0U
#define APIC_TIMER_MODE_PERIODIC    1U
#define APIC_TIMER_MODE_TSC_DEADLINE 2U

/* ================================================================
 * APIC state per partition
 *
 * In a full implementation this would be per-vCPU, but for BSP-only
 * single-socket operation, per-partition suffices.
 * ================================================================ */

struct fbvbs_apic_state {
    uint32_t mode;          /* 0=disabled, 1=xAPIC, 2=x2APIC */
    uint32_t apic_id;
    uint64_t apic_base;     /* IA32_APIC_BASE MSR value */
    uint32_t tpr;           /* Task Priority Register */
    uint32_t svr;           /* Spurious Vector Register */
    uint32_t lvt_timer;     /* LVT Timer entry */
    uint32_t timer_initial; /* Initial count */
    uint32_t timer_current; /* Current count (decrements) */
    uint32_t timer_divide;  /* Divide configuration */
    uint32_t esr;           /* Error Status Register */
    uint32_t icr_lo;        /* Interrupt Command Register (low) */
    uint32_t icr_hi;        /* Interrupt Command Register (high) */
    uint32_t isr[8];        /* In-Service Register (256 bits) */
    uint32_t irr[8];        /* Interrupt Request Register (256 bits) */
    uint32_t tmr[8];        /* Trigger Mode Register (256 bits) */
};

_Static_assert(sizeof(struct fbvbs_apic_state) <= 256U,
               "APIC state exceeds 256 bytes");

/* ================================================================
 * APIC mode detection
 * ================================================================ */

/*@ assigns \nothing;
    ensures \result == 0 || \result == 1 || \result == 2;
*/
int fbvbs_apic_detect_mode(void) {
    uint64_t apic_base_val;

    apic_base_val = fbvbs_asm_rdmsr(APIC_BASE_MSR);

    if ((apic_base_val & APIC_BASE_ENABLE) == 0U) {
        return 0;  /* APIC disabled */
    }
    if ((apic_base_val & APIC_BASE_X2APIC_ENABLE) != 0U) {
        return 2;  /* x2APIC mode */
    }
    return 1;  /* xAPIC mode */
}

/* ================================================================
 * APIC virtualization configuration builder
 *
 * Builds the VMX secondary proc-based control bits needed
 * for APIC virtualization, based on detected mode and
 * hardware capabilities.
 * ================================================================ */

/*@ requires \valid(config);
    requires \valid_read(caps);
    assigns *config;
    ensures \result == 0 || \result == -1;
*/
int fbvbs_apic_build_virt_config(
    struct fbvbs_apic_virt_config *config,
    const struct fbvbs_vmx_capabilities *caps)
{
    int mode;

    *config = (struct fbvbs_apic_virt_config){0};

    mode = fbvbs_apic_detect_mode();
    config->apic_mode = (uint32_t)mode;

    if (mode == 0) {
        return -1;  /* APIC disabled — cannot virtualize */
    }

    if (mode == 1) {
        /* xAPIC: use APIC access page for MMIO trapping.
         * The EPT maps APIC_DEFAULT_BASE to an APIC access page,
         * causing VM exits on guest APIC register accesses. */
        config->secondary_proc_or |= PROC2_VIRTUALIZE_APIC_ACCESSES;
        config->apic_access_page = APIC_DEFAULT_BASE;

        /* Enable APIC register virtualization for read acceleration.
         * Requires APIC virtualization capability (proc-based-controls2),
         * not HLAT. */
        if (caps->apic_virt_available != 0U) {
            config->secondary_proc_or |= PROC2_APIC_REGISTER_VIRT;
        }
    } else {
        /* x2APIC: use x2APIC mode virtualization (MSR-based).
         * Guest reads/writes to x2APIC MSRs are trapped via MSR bitmap
         * or virtualized directly. */
        config->secondary_proc_or |= PROC2_VIRTUALIZE_X2APIC_MODE;
    }

    /* Virtual interrupt delivery: accelerates interrupt injection
     * by allowing the hardware to evaluate and deliver pending
     * virtual interrupts without VM exits. */
    config->secondary_proc_or |= PROC2_VIRTUAL_INT_DELIVERY;

    /* Posted interrupts: allows external interrupts to be posted
     * directly to the guest without a VM exit (requires posted
     * interrupt descriptor in physical memory). */
    if (caps->posted_int_available != 0U) {
        config->pin_controls_or |= PIN_POSTED_INTERRUPTS;
    }

    return 0;
}

/* ================================================================
 * Virtual APIC state initialization
 * ================================================================ */

/* File-scope APIC state for BSP (single-socket model).
 * In a multi-vCPU system this would be per-vCPU. */
static struct fbvbs_apic_state bsp_apic_state;

/*@ requires \valid(apic);
    assigns *apic;
*/
static void fbvbs_apic_init_state(
    struct fbvbs_apic_state *apic,
    uint32_t apic_id)
{
    uint32_t i;

    *apic = (struct fbvbs_apic_state){0};
    apic->apic_id = apic_id;
    apic->apic_base = APIC_DEFAULT_BASE | APIC_BASE_ENABLE | APIC_BASE_BSP;
    apic->mode = 1;  /* Default to xAPIC */
    apic->svr = 0x000000FFU;  /* Spurious vector 0xFF, APIC disabled */
    apic->timer_divide = 0U;  /* Divide by 2 */

    /*@ loop invariant 0 <= i <= 8;
        loop assigns i, apic->isr[0 .. 7], apic->irr[0 .. 7], apic->tmr[0 .. 7];
        loop variant 8 - i;
    */
    for (i = 0; i < 8U; ++i) {
        apic->isr[i] = 0U;
        apic->irr[i] = 0U;
        apic->tmr[i] = 0U;
    }
}

/* ================================================================
 * EOI virtualization
 *
 * When the guest writes to the EOI register, the highest-priority
 * in-service interrupt is cleared and the next pending interrupt
 * (if any) is evaluated for delivery.
 *
 * With virtual interrupt delivery enabled, EOI writes that don't
 * require external notification are handled without VM exit.
 * ================================================================ */

/*@ requires \valid(apic);
    assigns apic->isr[0 .. 7];
    ensures \result == 0 || \result == -1;
*/
static int apic_handle_eoi(struct fbvbs_apic_state *apic) {
    uint32_t word;
    uint32_t bit;
    int32_t highest_isr = -1;

    /* Find highest-priority in-service interrupt */
    /*@ loop invariant 0 <= word <= 8;
        loop assigns word, bit, highest_isr;
        loop variant word;
    */
    for (word = 8U; word > 0U; --word) {
        uint32_t idx = word - 1U;
        if (apic->isr[idx] != 0U) {
            /* Find highest set bit */
            /*@ loop invariant 0 <= bit <= 32;
                loop assigns bit, highest_isr;
                loop variant bit;
            */
            for (bit = 32U; bit > 0U; --bit) {
                if ((apic->isr[idx] >> (bit - 1U)) & 1U) {
                    highest_isr = (int32_t)(idx * 32U + bit - 1U);
                    break;
                }
            }
            if (highest_isr >= 0) {
                break;
            }
        }
    }

    if (highest_isr < 0) {
        return -1;  /* No in-service interrupt */
    }

    /* Clear the ISR bit */
    word = (uint32_t)highest_isr / 32U;
    bit = (uint32_t)highest_isr % 32U;
    if (word < 8U) {
        apic->isr[word] &= ~(1U << bit);
    }

    return 0;
}

/* ================================================================
 * Virtual interrupt injection
 *
 * Sets a bit in the IRR (Interrupt Request Register) for delivery.
 * With virtual interrupt delivery, the hardware evaluates pending
 * IRR entries against TPR and delivers automatically.
 * ================================================================ */

/*@ requires \valid(apic);
    requires vector >= 16;
    assigns apic->irr[0 .. 7];
    ensures \result == 0 || \result == -1;
*/
static int apic_inject_interrupt(
    struct fbvbs_apic_state *apic,
    uint32_t vector)
{
    uint32_t word;
    uint32_t bit;

    if (vector > 255U) {
        return -1;
    }

    word = vector / 32U;
    bit = vector % 32U;

    if (word >= 8U) {
        return -1;
    }

    apic->irr[word] |= (1U << bit);
    return 0;
}

/* ================================================================
 * APIC timer virtualization
 *
 * The APIC timer decrements at the bus clock rate divided by the
 * divide configuration. When it reaches zero:
 *   - One-shot: stops, injects LVT timer vector
 *   - Periodic: reloads initial count, injects LVT timer vector
 *   - TSC-deadline: compares against IA32_TSC_DEADLINE MSR
 *
 * PRODUCTION NOTE: In production, the VMX preemption timer or
 * host APIC timer is used to emulate guest APIC timer expiry.
 * This model function simulates the expiry check.
 * ================================================================ */

/*@ requires \valid(apic);
    assigns apic->timer_current, apic->irr[0 .. 7];
    ensures \result == 0 || \result == 1;
*/
static int apic_timer_check_expiry(struct fbvbs_apic_state *apic) {
    uint32_t vector;
    uint32_t timer_mode;

    if (apic->timer_initial == 0U) {
        return 0;  /* Timer not armed */
    }

    /* Check if timer expired (model: decrement to zero) */
    if (apic->timer_current > 0U) {
        apic->timer_current -= 1U;
    }

    if (apic->timer_current != 0U) {
        return 0;  /* Not yet expired */
    }

    /* Timer expired — extract vector and mode from LVT */
    vector = apic->lvt_timer & 0xFFU;
    timer_mode = (apic->lvt_timer >> 17U) & 0x3U;

    /* Check if masked */
    if ((apic->lvt_timer & (1U << 16U)) != 0U) {
        /* Masked — reload if periodic, else stay stopped */
        if (timer_mode == APIC_TIMER_MODE_PERIODIC) {
            apic->timer_current = apic->timer_initial;
        }
        return 0;
    }

    /* Inject the timer interrupt */
    if (vector >= 16U) {
        (void)apic_inject_interrupt(apic, vector);
    }

    /* Reload for periodic mode */
    if (timer_mode == APIC_TIMER_MODE_PERIODIC) {
        apic->timer_current = apic->timer_initial;
    }

    return 1;  /* Timer fired */
}

/* ================================================================
 * Public API: APIC virtualization for partition VM entry/exit
 * ================================================================ */

/*@ assigns \nothing;
    ensures \result == 0 || \result == 1 || \result == 2;
*/
int fbvbs_apic_get_mode(void) {
    return fbvbs_apic_detect_mode();
}

/*@ assigns bsp_apic_state;
    ensures \result == 0;
*/
int fbvbs_apic_init_partition(uint32_t apic_id) {
    fbvbs_apic_init_state(&bsp_apic_state, apic_id);
    return 0;
}

/*@ assigns bsp_apic_state.isr[0 .. 7];
    ensures \result == 0 || \result == -1;
*/
int fbvbs_apic_handle_vm_exit_eoi(void) {
    return apic_handle_eoi(&bsp_apic_state);
}

/*@ assigns bsp_apic_state.irr[0 .. 7];
    ensures \result == 0 || \result == -1;
*/
int fbvbs_apic_inject_vector(uint32_t vector) {
    if (vector < 16U || vector > 255U) {
        return -1;
    }
    return apic_inject_interrupt(&bsp_apic_state, vector);
}

/*@ assigns bsp_apic_state.timer_current, bsp_apic_state.irr[0 .. 7];
    ensures \result == 0 || \result == 1;
*/
int fbvbs_apic_timer_tick(void) {
    return apic_timer_check_expiry(&bsp_apic_state);
}
