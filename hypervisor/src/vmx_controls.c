#include "fbvbs_asm.h"
#include "fbvbs_hypervisor.h"

/* ================================================================
 * VMX Execution Controls: CET, MSR Bitmap, Preemption Timer
 *
 * Phase 2-3: CET Shadow Stack integration
 * Phase 2-4: MSR bitmap and intercept configuration
 * Phase 2-5: VMX Preemption Timer and Notify VM Exit
 *
 * These functions configure VMCS control fields for security-
 * critical VMX features. They produce configuration values that
 * must be applied via VMWRITE in assembly.
 *
 * Requirements: REQ-0332 (Shadow Stack EPT)
 *
 * Reference: Intel SDM Vol. 3, Chapter 24-26
 * ================================================================ */

/* ================================================================
 * Phase 2-3: CET (Control-flow Enforcement Technology)
 *
 * CET provides two complementary security mechanisms:
 * - Shadow Stack (CET-SS): maintains a protected return address
 *   stack that the CPU compares against on RET instructions
 * - Indirect Branch Tracking (CET-IBT): requires ENDBRANCH
 *   instruction at indirect branch targets
 *
 * The hypervisor must:
 * 1. Enable CET for itself (CR4.CET, IA32_S_CET)
 * 2. Save/restore per-vCPU CET MSRs on partition transitions
 * 3. Configure EPT attributes for shadow stack pages
 * 4. Intercept CET MSR writes for policy enforcement
 *
 * VMCS CET-related fields:
 *   Guest IA32_S_CET (0x6826)
 *   Guest SSP (0x682C)
 *   Guest IA32_INTERRUPT_SSP_TABLE_ADDR (0x6830)
 *   Host IA32_S_CET (0x6C18)
 *   Host SSP (0x6C1C)
 *   Host IA32_INTERRUPT_SSP_TABLE_ADDR (0x6C20)
 * ================================================================ */

/* CET MSR addresses */
#define MSR_IA32_U_CET                  0x000006A0U
#define MSR_IA32_S_CET                  0x000006A2U
#define MSR_IA32_PL0_SSP                0x000006A4U
#define MSR_IA32_PL1_SSP                0x000006A5U
#define MSR_IA32_PL2_SSP                0x000006A6U
#define MSR_IA32_PL3_SSP                0x000006A7U
#define MSR_IA32_ISST_ADDR              0x000006A8U

/* VMX control MSR addresses */
#define MSR_IA32_VMX_PROCBASED_CTLS2    0x0000048BU
#define MSR_IA32_VMX_PROCBASED_CTLS3    0x00000492U

/* IA32_S_CET bits */
#define S_CET_SH_STK_EN                (1ULL << 0)
#define S_CET_WR_SHSTK_EN              (1ULL << 1)
#define S_CET_ENDBR_EN                  (1ULL << 2)

/* VMCS CET field encodings */
#define VMCS_GUEST_S_CET                0x6826U
#define VMCS_GUEST_SSP                  0x682CU
#define VMCS_GUEST_ISST_ADDR            0x6830U
#define VMCS_HOST_S_CET                 0x6C18U
#define VMCS_HOST_SSP                   0x6C1CU
#define VMCS_HOST_ISST_ADDR             0x6C20U

/* VM entry/exit controls for CET */
#define ENTRY_LOAD_CET_STATE            (1U << 20)
#define EXIT_LOAD_CET_STATE             (1U << 28)

/* CET VMCS configuration */
struct fbvbs_cet_vmcs_config {
    uint32_t entry_controls_or;   /* Bits to OR into entry controls */
    uint32_t exit_controls_or;    /* Bits to OR into exit controls */
    uint64_t host_s_cet;
    uint64_t host_ssp;
    uint64_t host_isst_addr;
    uint64_t guest_s_cet;
    uint64_t guest_ssp;
    uint64_t guest_isst_addr;
};

static uint64_t g_msr_bitmap_phys;

/* Retained-C bare-metal keeps allocator-backed control pages reachable via the
 * identity map, and hosted/unit-test builds return page-backed virtual
 * addresses from fbvbs_page_alloc().  VMX control initialization therefore
 * treats the returned physical page as directly writable at this stage. */
/*@ assigns \nothing;
    ensures \result == \null || \valid(((uint8_t *)\result) + (0 .. FBVBS_PAGE_SIZE - 1));
*/
static uint8_t *fbvbs_page_phys_to_writable_ptr(uint64_t phys_addr)
{
    if (phys_addr == 0ULL) {
        return NULL;
    }
    return (uint8_t *)(uintptr_t)phys_addr;
}

/*@ requires \valid(config);
    requires \valid_read(caps);
    assigns *config;
    ensures \result == 0 || \result == -1;
*/
static int fbvbs_cet_build_vmcs_config(
    struct fbvbs_cet_vmcs_config *config,
    const struct fbvbs_vmx_capabilities *caps)
{
    *config = (struct fbvbs_cet_vmcs_config){0};

    if (caps->cet_available == 0U) {
        return -1;  /* CET not supported */
    }

    /* Entry/Exit controls: load CET state on transitions */
    config->entry_controls_or = ENTRY_LOAD_CET_STATE;
    config->exit_controls_or = EXIT_LOAD_CET_STATE;

    /* Host CET: enable shadow stack + IBT for hypervisor itself */
    config->host_s_cet = S_CET_SH_STK_EN | S_CET_ENDBR_EN;

    /* Allocate shadow stack page for the hypervisor.
     * PRODUCTION NOTE: This page must have Supervisor Shadow Stack
     * EPT attributes. The ISST (Interrupt SSP Table) page stores
     * per-IST shadow stack pointers for NMI/MC/DF handlers. */
    {
        uint64_t ssp_page = fbvbs_page_alloc();
        uint64_t isst_page;
        if (ssp_page == 0ULL) {
            /* CET requires shadow stack pages — fail-closed */
            return -1;
        }
        isst_page = fbvbs_page_alloc();
        if (isst_page == 0ULL) {
            (void)fbvbs_page_free(ssp_page);
            return -1;
        }
        /* SSP points to end of page (stack grows down) */
        config->host_ssp = ssp_page + 4096ULL - 8ULL;
        config->host_isst_addr = isst_page;
    }

    /* Guest CET: enable shadow stack for FreeBSD kernel */
    config->guest_s_cet = S_CET_SH_STK_EN;
    /* guest_ssp set by FreeBSD on boot — loaded from VMCS */

    return 0;
}

/* CET MSR save/restore is handled at VM exit/entry time by cpu_security.c.
 * Initialization must not temporarily write CET state. */

/*@ assigns \result \from g_msr_bitmap_phys;
*/
uint64_t fbvbs_vmx_get_msr_bitmap_phys(void)
{
    return g_msr_bitmap_phys;
}

/*@ assigns \result \from msr, bit;
*/
static int vmx_control_msr_bit_allowed(uint32_t msr, uint32_t bit)
{
#if defined(FBVBS_BAREMETAL_BUILD) && (defined(__x86_64__) || defined(__i386__))
    uint64_t value = fbvbs_asm_rdmsr(msr);
    return ((value >> 32U) & (1ULL << bit)) != 0U;
#else
    (void)msr;
    (void)bit;
    return 0;
#endif
}

/* ================================================================
 * Phase 2-4: MSR Bitmap Configuration
 *
 * The MSR bitmap is a 4KB structure that controls which MSR
 * accesses cause VM exits. For each MSR, separate bits control
 * RDMSR and WRMSR exits.
 *
 * Layout: 4 × 1KB regions
 *   [0x000-0x3FF] Read bitmap for low MSRs (0x00000000-0x00001FFF)
 *   [0x400-0x7FF] Read bitmap for high MSRs (0xC0000000-0xC0001FFF)
 *   [0x800-0xBFF] Write bitmap for low MSRs
 *   [0xC00-0xFFF] Write bitmap for high MSRs
 *
 * Bit=1 means VM exit on access, Bit=0 means allow.
 *
 * Security policy: intercept all security-relevant MSRs to
 * prevent the guest from disabling mitigations.
 * ================================================================ */

#define MSR_BITMAP_SIZE             4096U
#define MSR_BITMAP_READ_LOW_OFFSET  0x000U
#define MSR_BITMAP_READ_HIGH_OFFSET 0x400U
#define MSR_BITMAP_WRITE_LOW_OFFSET 0x800U
#define MSR_BITMAP_WRITE_HIGH_OFFSET 0xC00U

/* Security-critical MSRs that must be intercepted */
#define MSR_IA32_SPEC_CTRL              0x00000048U
#define MSR_IA32_PRED_CMD               0x00000049U
#define MSR_IA32_FLUSH_CMD              0x0000010BU
#define MSR_IA32_TSX_CTRL               0x00000122U
#define MSR_IA32_MCU_OPT_CTRL           0x00000123U
#define MSR_IA32_ARCH_CAPABILITIES      0x0000010AU
#define MSR_IA32_DEBUGCTL               0x000001D9U
#define MSR_IA32_SYSENTER_CS            0x00000174U
#define MSR_IA32_SYSENTER_ESP           0x00000175U
#define MSR_IA32_SYSENTER_EIP           0x00000176U
#define MSR_IA32_EFER                   0xC0000080U
#define MSR_IA32_STAR                   0xC0000081U
#define MSR_IA32_LSTAR                  0xC0000082U
#define MSR_IA32_FMASK                  0xC0000084U
#define MSR_IA32_KERNEL_GS_BASE         0xC0000102U

/* Intel PT MSRs (REQ-0344) */
#define MSR_IA32_RTIT_CTL               0x00000570U
#define MSR_IA32_RTIT_STATUS            0x00000571U
#define MSR_IA32_RTIT_OUTPUT_BASE       0x00000560U
#define MSR_IA32_RTIT_OUTPUT_MASK       0x00000561U

/* Model MSR bitmap: production uses a 4KB-aligned physical page */
struct fbvbs_msr_bitmap_model {
    uint8_t data[MSR_BITMAP_SIZE];
};

/* Set intercept bit for a low-range MSR (0x00000000-0x00001FFF) */
/*@ requires \valid(bitmap);
    requires msr_addr <= 0x1FFFU;
    assigns bitmap->data[MSR_BITMAP_WRITE_LOW_OFFSET .. MSR_BITMAP_WRITE_LOW_OFFSET + 0x3FFU];
*/
static void msr_bitmap_intercept_write_low(
    struct fbvbs_msr_bitmap_model *bitmap,
    uint32_t msr_addr)
{
    uint32_t byte_offset = MSR_BITMAP_WRITE_LOW_OFFSET + (msr_addr / 8U);
    uint8_t bit_mask = (uint8_t)(1U << (msr_addr % 8U));

    if (byte_offset < MSR_BITMAP_SIZE) {
        bitmap->data[byte_offset] |= bit_mask;
    }
}

/* Set intercept bit for a high-range MSR (0xC0000000-0xC0001FFF) */
/*@ requires \valid(bitmap);
    requires msr_addr >= 0xC0000000U;
    requires msr_addr <= 0xC0001FFFU;
    assigns bitmap->data[MSR_BITMAP_WRITE_HIGH_OFFSET .. MSR_BITMAP_WRITE_HIGH_OFFSET + 0x3FFU];
*/
static void msr_bitmap_intercept_write_high(
    struct fbvbs_msr_bitmap_model *bitmap,
    uint32_t msr_addr)
{
    uint32_t index = msr_addr - 0xC0000000U;
    uint32_t byte_offset = MSR_BITMAP_WRITE_HIGH_OFFSET + (index / 8U);
    uint8_t bit_mask = (uint8_t)(1U << (index % 8U));

    if (byte_offset < MSR_BITMAP_SIZE) {
        bitmap->data[byte_offset] |= bit_mask;
    }
}

/* Set intercept for read of a low-range MSR */
/*@ requires \valid(bitmap);
    requires msr_addr <= 0x1FFFU;
    assigns bitmap->data[MSR_BITMAP_READ_LOW_OFFSET .. MSR_BITMAP_READ_LOW_OFFSET + 0x3FFU];
*/
static void msr_bitmap_intercept_read_low(
    struct fbvbs_msr_bitmap_model *bitmap,
    uint32_t msr_addr)
{
    uint32_t byte_offset = MSR_BITMAP_READ_LOW_OFFSET + (msr_addr / 8U);
    uint8_t bit_mask = (uint8_t)(1U << (msr_addr % 8U));

    if (byte_offset < MSR_BITMAP_SIZE) {
        bitmap->data[byte_offset] |= bit_mask;
    }
}

/*@ requires \valid(bitmap);
    assigns bitmap->data[0 .. MSR_BITMAP_SIZE - 1];
*/
static void fbvbs_msr_bitmap_init(struct fbvbs_msr_bitmap_model *bitmap)
{
    uint32_t i;

    /* Start with all MSRs allowed (0 = no exit) */
    /*@ loop invariant 0 <= i <= MSR_BITMAP_SIZE;
        loop assigns i, bitmap->data[0 .. MSR_BITMAP_SIZE - 1];
        loop variant MSR_BITMAP_SIZE - i;
    */
    for (i = 0U; i < MSR_BITMAP_SIZE; ++i) {
        bitmap->data[i] = 0U;
    }

    /* Intercept writes to speculation control MSRs (REQ-0340) */
    msr_bitmap_intercept_write_low(bitmap, MSR_IA32_SPEC_CTRL);
    msr_bitmap_intercept_write_low(bitmap, MSR_IA32_PRED_CMD);
    msr_bitmap_intercept_write_low(bitmap, MSR_IA32_FLUSH_CMD);
    msr_bitmap_intercept_write_low(bitmap, MSR_IA32_TSX_CTRL);
    msr_bitmap_intercept_write_low(bitmap, MSR_IA32_MCU_OPT_CTRL);

    /* Intercept reads of architectural capabilities (information leak) */
    msr_bitmap_intercept_read_low(bitmap, MSR_IA32_ARCH_CAPABILITIES);

    /* Intercept writes to debug/trace MSRs (REQ-0342, REQ-0344) */
    msr_bitmap_intercept_write_low(bitmap, MSR_IA32_DEBUGCTL);
    msr_bitmap_intercept_write_low(bitmap, MSR_IA32_RTIT_CTL);
    msr_bitmap_intercept_write_low(bitmap, MSR_IA32_RTIT_STATUS);
    msr_bitmap_intercept_write_low(bitmap, MSR_IA32_RTIT_OUTPUT_BASE);
    msr_bitmap_intercept_write_low(bitmap, MSR_IA32_RTIT_OUTPUT_MASK);

    /* Intercept writes to SYSENTER MSRs (control flow targets) */
    msr_bitmap_intercept_write_low(bitmap, MSR_IA32_SYSENTER_CS);
    msr_bitmap_intercept_write_low(bitmap, MSR_IA32_SYSENTER_ESP);
    msr_bitmap_intercept_write_low(bitmap, MSR_IA32_SYSENTER_EIP);

    /* Intercept writes to CET MSRs (REQ-0331) */
    msr_bitmap_intercept_write_low(bitmap, MSR_IA32_S_CET);
    msr_bitmap_intercept_write_low(bitmap, MSR_IA32_U_CET);
    msr_bitmap_intercept_write_low(bitmap, MSR_IA32_PL0_SSP);
    msr_bitmap_intercept_write_low(bitmap, MSR_IA32_PL1_SSP);
    msr_bitmap_intercept_write_low(bitmap, MSR_IA32_PL2_SSP);
    msr_bitmap_intercept_write_low(bitmap, MSR_IA32_PL3_SSP);
    msr_bitmap_intercept_write_low(bitmap, MSR_IA32_ISST_ADDR);

    /* Intercept writes to SYSCALL/SYSRET MSRs (high range) */
    msr_bitmap_intercept_write_high(bitmap, MSR_IA32_EFER);
    msr_bitmap_intercept_write_high(bitmap, MSR_IA32_STAR);
    msr_bitmap_intercept_write_high(bitmap, MSR_IA32_LSTAR);
    msr_bitmap_intercept_write_high(bitmap, MSR_IA32_FMASK);
    msr_bitmap_intercept_write_high(bitmap, MSR_IA32_KERNEL_GS_BASE);
}

/* ================================================================
 * Phase 2-5: VMX Preemption Timer and Notify VM Exit
 *
 * The VMX preemption timer causes a VM exit after a specified
 * number of TSC ticks, preventing a guest from monopolizing
 * the CPU (REQ-0370).
 *
 * Notify VM Exit (REQ-0371): when enabled, certain architectural
 * events (bus locks, long-running instructions) cause VM exits
 * with a "notify" reason, allowing the hypervisor to detect and
 * prevent guest CPU-monopolization attacks.
 *
 * Bus Lock VM Exit: a guest acquiring a bus lock (split-lock or
 * UC/WC memory access with LOCK prefix) causes a VM exit,
 * preventing cross-core performance degradation attacks.
 * ================================================================ */

/* VMCS fields */
#define VMCS_VMX_PREEMPTION_TIMER_VALUE 0x482EU
#define VMCS_NOTIFY_WINDOW              0x4024U

/* Pin-based control bits */
#define PIN_VMX_PREEMPTION_TIMER        (1U << 6)

/* Secondary processor-based control bits */
#define PROC2_BUS_LOCK_DETECT           (1U << 30)

/* Tertiary processor-based control bits */
#define PROC3_NOTIFY_VM_EXIT            (1ULL << 3)

/* Default preemption timer value: ~10ms at 2GHz TSC
 * Actual value should be calibrated from IA32_VMX_MISC[4:0]
 * which gives the TSC-to-timer rate shift. */
#define FBVBS_DEFAULT_PREEMPTION_TICKS  20000000U

/* Notify window: 0 = immediate notify on triggering event */
#define FBVBS_DEFAULT_NOTIFY_WINDOW     0U

struct fbvbs_preemption_config {
    uint32_t pin_controls_or;         /* OR into pin-based controls */
    uint32_t secondary_controls_or;   /* OR into secondary proc controls */
    uint64_t tertiary_controls_or;    /* OR into tertiary proc controls */
    uint32_t preemption_timer_value;
    uint32_t notify_window;
};

/*@ requires \valid(config);
    requires \valid_read(caps);
    assigns *config;
*/
static void fbvbs_preemption_build_config(
    struct fbvbs_preemption_config *config,
    const struct fbvbs_vmx_capabilities *caps)
{
    *config = (struct fbvbs_preemption_config){0};
    (void)caps;

    /* Always enable preemption timer (REQ-0370) */
    config->pin_controls_or = PIN_VMX_PREEMPTION_TIMER;
    config->preemption_timer_value = FBVBS_DEFAULT_PREEMPTION_TICKS;

    /* Bus lock detection if allowed by IA32_VMX_PROCBASED_CTLS2. */
    if (vmx_control_msr_bit_allowed(MSR_IA32_VMX_PROCBASED_CTLS2, 30U) != 0) {
        config->secondary_controls_or = PROC2_BUS_LOCK_DETECT;
    }

    /* Notify VM Exit if allowed by IA32_VMX_PROCBASED_CTLS3. */
    if (vmx_control_msr_bit_allowed(MSR_IA32_VMX_PROCBASED_CTLS3, 3U) != 0) {
        config->tertiary_controls_or = PROC3_NOTIFY_VM_EXIT;
        config->notify_window = FBVBS_DEFAULT_NOTIFY_WINDOW;
    }
}

/* ================================================================
 * Public API: Build complete VMX security controls
 *
 * Combines CET, MSR bitmap, preemption timer, and notify exit
 * configurations into a unified set of VMCS control field
 * modifications.
 * ================================================================ */

int fbvbs_vmx_build_security_controls(
    struct fbvbs_vmx_security_controls *controls,
    const struct fbvbs_vmx_capabilities *caps)
{
    /* MSR bitmap is 4KB — too large for hypervisor stack (16-64KiB).
     * Use file-scope static. Single-threaded init path, no race. */
    static struct fbvbs_msr_bitmap_model bitmap;
    struct fbvbs_preemption_config preempt;
    struct fbvbs_cet_vmcs_config cet_config = {0};
    uint64_t bitmap_phys;

    *controls = (struct fbvbs_vmx_security_controls){0};

    /* Preemption timer + notify exit */
    fbvbs_preemption_build_config(&preempt, caps);
    controls->pin_controls_or |= preempt.pin_controls_or;
    controls->secondary_proc_or |= preempt.secondary_controls_or;
    controls->tertiary_proc_or |= preempt.tertiary_controls_or;
    controls->preemption_timer_value = preempt.preemption_timer_value;
    controls->notify_window = preempt.notify_window;

    /* CET if available — fail-closed: if hardware supports CET but
     * allocation fails, the entire security controls init fails.
     * Running without CET on CET-capable hardware is a downgrade. */
    if (caps->cet_available != 0U) {
        if (fbvbs_cet_build_vmcs_config(&cet_config, caps) != 0) {
            return -1;  /* CET available but SSP/ISST alloc failed */
        }
        controls->entry_controls_or |= cet_config.entry_controls_or;
        controls->exit_controls_or |= cet_config.exit_controls_or;
        controls->host_s_cet = cet_config.host_s_cet;
        controls->host_ssp = cet_config.host_ssp;
        controls->host_isst_addr = cet_config.host_isst_addr;
        controls->guest_s_cet = cet_config.guest_s_cet;
    }

    /* MSR bitmap — always initialize after CET setup succeeds. */
    fbvbs_msr_bitmap_init(&bitmap);
    bitmap_phys = g_msr_bitmap_phys;
    if (bitmap_phys == 0U) {
        bitmap_phys = fbvbs_page_alloc();
        if (bitmap_phys == 0U) {
            if (caps->cet_available != 0U) {
                uint64_t host_ssp_page = cet_config.host_ssp & ~((uint64_t)FBVBS_PAGE_SIZE - 1ULL);
                if (host_ssp_page != 0U) {
                    (void)fbvbs_page_free(host_ssp_page);
                }
                if (cet_config.host_isst_addr != 0U) {
                    (void)fbvbs_page_free(cet_config.host_isst_addr);
                }
            }
            return -1;
        }
        g_msr_bitmap_phys = bitmap_phys;
    }
    {
        uint8_t *bitmap_ptr = fbvbs_page_phys_to_writable_ptr(bitmap_phys);
        if (bitmap_ptr == NULL) {
            return -1;
        }
        fbvbs_copy_bytes(bitmap_ptr, bitmap.data, sizeof(bitmap.data));
    }
    controls->msr_bitmap_valid = 1;

    /* The MSR bitmap physical page is exposed via fbvbs_vmx_get_msr_bitmap_phys()
     * and written into VMCS_MSR_BITMAP by vmcs_setup.c. */

    return 0;
}
