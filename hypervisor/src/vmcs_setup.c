#include "fbvbs_hypervisor.h"
#include "fbvbs_asm.h"

/* ================================================================
 * VMCS (Virtual Machine Control Structure) Setup for FreeBSD Host
 *
 * Configures the VMCS fields required to run FreeBSD as a
 * deprivileged guest in VMX non-root operation. This module
 * provides the C-level field setup; actual VMWRITE/VMREAD/VMLAUNCH
 * require assembly support code.
 *
 * Reference: Intel SDM Vol. 3, Chapter 24 (VMCS Fields)
 *            Intel SDM Vol. 3, Chapter 25 (VM Entries)
 *            Intel SDM Vol. 3, Chapter 26 (VM Exits)
 * ================================================================ */

/* ================================================================
 * VMCS field encodings (Intel SDM Appendix B)
 * ================================================================ */

/* 16-bit control fields */
#define VMCS_VPID                       0x0000U
#define VMCS_POSTED_INTR_NV             0x0002U

/* 16-bit guest-state fields */
#define VMCS_GUEST_ES_SELECTOR          0x0800U
#define VMCS_GUEST_CS_SELECTOR          0x0802U
#define VMCS_GUEST_SS_SELECTOR          0x0804U
#define VMCS_GUEST_DS_SELECTOR          0x0806U
#define VMCS_GUEST_FS_SELECTOR          0x0808U
#define VMCS_GUEST_GS_SELECTOR          0x080AU
#define VMCS_GUEST_LDTR_SELECTOR        0x080CU
#define VMCS_GUEST_TR_SELECTOR          0x080EU

/* 16-bit host-state fields */
#define VMCS_HOST_ES_SELECTOR           0x0C00U
#define VMCS_HOST_CS_SELECTOR           0x0C02U
#define VMCS_HOST_SS_SELECTOR           0x0C04U
#define VMCS_HOST_DS_SELECTOR           0x0C06U
#define VMCS_HOST_FS_SELECTOR           0x0C08U
#define VMCS_HOST_GS_SELECTOR          0x0C0AU
#define VMCS_HOST_TR_SELECTOR           0x0C0CU

/* 64-bit control fields */
#define VMCS_IO_BITMAP_A                0x2000U
#define VMCS_IO_BITMAP_B                0x2002U
#define VMCS_MSR_BITMAP                 0x2004U
#define VMCS_EXIT_MSR_STORE_ADDR        0x2006U
#define VMCS_EXIT_MSR_LOAD_ADDR         0x2008U
#define VMCS_ENTRY_MSR_LOAD_ADDR        0x200AU
#define VMCS_EPT_POINTER                0x201AU
#define VMCS_TSC_OFFSET                 0x2010U

/* 64-bit guest-state fields */
#define VMCS_GUEST_IA32_DEBUGCTL        0x2802U
#define VMCS_GUEST_IA32_PAT             0x2804U
#define VMCS_GUEST_IA32_EFER            0x2806U

/* 64-bit host-state fields */
#define VMCS_HOST_IA32_PAT              0x2C00U
#define VMCS_HOST_IA32_EFER             0x2C02U

/* 32-bit control fields */
#define VMCS_PIN_BASED_CONTROLS         0x4000U
#define VMCS_PRIMARY_PROC_CONTROLS      0x4002U
#define VMCS_EXCEPTION_BITMAP           0x4004U
#define VMCS_PAGE_FAULT_ERROR_CODE_MASK 0x4006U
#define VMCS_PAGE_FAULT_ERROR_CODE_MATCH 0x4008U
#define VMCS_CR3_TARGET_COUNT           0x400AU
#define VMCS_EXIT_CONTROLS              0x400CU
#define VMCS_EXIT_MSR_STORE_COUNT       0x400EU
#define VMCS_EXIT_MSR_LOAD_COUNT        0x4010U
#define VMCS_ENTRY_CONTROLS             0x4012U
#define VMCS_ENTRY_MSR_LOAD_COUNT       0x4014U
#define VMCS_ENTRY_INTR_INFO            0x4016U
#define VMCS_SECONDARY_PROC_CONTROLS    0x401EU

/* 32-bit guest-state fields */
#define VMCS_GUEST_ES_LIMIT             0x4800U
#define VMCS_GUEST_CS_LIMIT             0x4802U
#define VMCS_GUEST_SS_LIMIT             0x4804U
#define VMCS_GUEST_DS_LIMIT             0x4806U
#define VMCS_GUEST_FS_LIMIT             0x4808U
#define VMCS_GUEST_GS_LIMIT             0x480AU
#define VMCS_GUEST_LDTR_LIMIT           0x480CU
#define VMCS_GUEST_TR_LIMIT             0x480EU
#define VMCS_GUEST_GDTR_LIMIT           0x4810U
#define VMCS_GUEST_IDTR_LIMIT           0x4812U
#define VMCS_GUEST_ES_ACCESS_RIGHTS     0x4814U
#define VMCS_GUEST_CS_ACCESS_RIGHTS     0x4816U
#define VMCS_GUEST_SS_ACCESS_RIGHTS     0x4818U
#define VMCS_GUEST_DS_ACCESS_RIGHTS     0x481AU
#define VMCS_GUEST_FS_ACCESS_RIGHTS     0x481CU
#define VMCS_GUEST_GS_ACCESS_RIGHTS     0x481EU
#define VMCS_GUEST_LDTR_ACCESS_RIGHTS   0x4820U
#define VMCS_GUEST_TR_ACCESS_RIGHTS     0x4822U
#define VMCS_GUEST_INTERRUPTIBILITY     0x4824U
#define VMCS_GUEST_ACTIVITY_STATE       0x4826U
#define VMCS_GUEST_SYSENTER_CS          0x482AU

/* Natural-width guest-state fields */
#define VMCS_GUEST_CR0                  0x6800U
#define VMCS_GUEST_CR3                  0x6802U
#define VMCS_GUEST_CR4                  0x6804U
#define VMCS_GUEST_ES_BASE              0x6806U
#define VMCS_GUEST_CS_BASE              0x6808U
#define VMCS_GUEST_SS_BASE              0x680AU
#define VMCS_GUEST_DS_BASE              0x680CU
#define VMCS_GUEST_FS_BASE              0x680EU
#define VMCS_GUEST_GS_BASE              0x6810U
#define VMCS_GUEST_LDTR_BASE            0x6812U
#define VMCS_GUEST_TR_BASE              0x6814U
#define VMCS_GUEST_GDTR_BASE            0x6816U
#define VMCS_GUEST_IDTR_BASE            0x6818U
#define VMCS_GUEST_DR7                  0x681AU
#define VMCS_GUEST_RSP                  0x681CU
#define VMCS_GUEST_RIP                  0x681EU
#define VMCS_GUEST_RFLAGS               0x6820U
#define VMCS_GUEST_SYSENTER_ESP         0x6824U
#define VMCS_GUEST_SYSENTER_EIP         0x6826U

/* Natural-width host-state fields */
#define VMCS_HOST_CR0                   0x6C00U
#define VMCS_HOST_CR3                   0x6C02U
#define VMCS_HOST_CR4                   0x6C04U
#define VMCS_HOST_FS_BASE               0x6C06U
#define VMCS_HOST_GS_BASE               0x6C08U
#define VMCS_HOST_TR_BASE               0x6C0AU
#define VMCS_HOST_GDTR_BASE             0x6C0CU
#define VMCS_HOST_IDTR_BASE             0x6C0EU
#define VMCS_HOST_SYSENTER_ESP          0x6C10U
#define VMCS_HOST_SYSENTER_EIP          0x6C12U
#define VMCS_HOST_RSP                   0x6C14U
#define VMCS_HOST_RIP                   0x6C16U

/* Natural-width control fields */
#define VMCS_CR0_GUEST_HOST_MASK        0x6000U
#define VMCS_CR4_GUEST_HOST_MASK        0x6002U
#define VMCS_CR0_READ_SHADOW            0x6004U
#define VMCS_CR4_READ_SHADOW            0x6006U

/* ================================================================
 * VM Execution Control Bits
 * ================================================================ */

/* Pin-based controls */
#define PIN_EXTERNAL_INTERRUPT_EXITING  (1U << 0)
#define PIN_NMI_EXITING                 (1U << 3)
#define PIN_VIRTUAL_NMIS                (1U << 5)

/* Primary processor-based controls */
#define PROC_HLT_EXITING               (1U << 7)
#define PROC_INVLPG_EXITING             (1U << 9)
#define PROC_MWAIT_EXITING              (1U << 10)
#define PROC_RDPMC_EXITING              (1U << 11)
#define PROC_RDTSC_EXITING              (1U << 12)
#define PROC_CR3_LOAD_EXITING           (1U << 15)
#define PROC_CR3_STORE_EXITING          (1U << 16)
#define PROC_CR8_LOAD_EXITING           (1U << 19)
#define PROC_CR8_STORE_EXITING          (1U << 20)
#define PROC_MOV_DR_EXITING             (1U << 23)
#define PROC_UNCONDITIONAL_IO_EXITING   (1U << 24)
#define PROC_USE_IO_BITMAPS             (1U << 25)
#define PROC_USE_MSR_BITMAPS            (1U << 28)
#define PROC_MONITOR_EXITING            (1U << 29)
#define PROC_PAUSE_EXITING              (1U << 30)
#define PROC_ACTIVATE_SECONDARY         (1U << 31)

/* Secondary processor-based controls */
#define PROC2_ENABLE_EPT                (1U << 1)
#define PROC2_RDTSCP                    (1U << 3)
#define PROC2_ENABLE_VPID               (1U << 5)
#define PROC2_UNRESTRICTED_GUEST        (1U << 7)
#define PROC2_ENABLE_INVPCID            (1U << 12)
#define PROC2_ENABLE_XSAVES            (1U << 20)

/* VM-exit controls */
#define EXIT_HOST_ADDR_SPACE_SIZE       (1U << 9)   /* 64-bit host */
#define EXIT_SAVE_IA32_PAT              (1U << 18)
#define EXIT_LOAD_IA32_PAT              (1U << 19)
#define EXIT_SAVE_IA32_EFER             (1U << 20)
#define EXIT_LOAD_IA32_EFER             (1U << 21)

/* VM-entry controls */
#define ENTRY_IA32E_MODE_GUEST          (1U << 9)   /* 64-bit guest */
#define ENTRY_LOAD_IA32_PAT             (1U << 14)
#define ENTRY_LOAD_IA32_EFER            (1U << 15)

/* ================================================================
 * VMCS field configuration structure
 *
 * Collects all the values needed to write into a VMCS before
 * launching a guest. Production code would call VMWRITE for each.
 * ================================================================ */

struct fbvbs_vmcs_config {
    /* Control fields */
    uint32_t pin_based_controls;
    uint32_t primary_proc_controls;
    uint32_t secondary_proc_controls;
    uint32_t exit_controls;
    uint32_t entry_controls;
    uint32_t exception_bitmap;

    /* VPID — unique per vCPU (REQ-0341), 0 is reserved */
    uint16_t vpid;
    uint16_t reserved_vpid;

    /* CR mask/shadow (for CR0/CR4 interception) */
    uint64_t cr0_guest_host_mask;
    uint64_t cr4_guest_host_mask;
    uint64_t cr0_read_shadow;
    uint64_t cr4_read_shadow;

    /* EPT pointer (points to EPT PML4) */
    uint64_t ept_pointer;

    /* Host state (hypervisor's own register values) */
    uint64_t host_cr0;
    uint64_t host_cr3;
    uint64_t host_cr4;
    uint64_t host_rsp;
    uint64_t host_rip;       /* VM-exit entry point (assembly) */
    uint64_t host_gdtr_base;
    uint64_t host_idtr_base;
    uint64_t host_tr_base;
    uint64_t host_efer;
    uint16_t host_cs;
    uint16_t host_ss;
    uint16_t host_ds;
    uint16_t host_es;
    uint16_t host_fs;
    uint16_t host_gs;
    uint16_t host_tr;
    uint16_t reserved0;

    /* Guest state (FreeBSD's initial register values) */
    uint64_t guest_cr0;
    uint64_t guest_cr3;
    uint64_t guest_cr4;
    uint64_t guest_rsp;
    uint64_t guest_rip;
    uint64_t guest_rflags;
    uint64_t guest_efer;
    uint64_t guest_gdtr_base;
    uint32_t guest_gdtr_limit;
    uint64_t guest_idtr_base;
    uint32_t guest_idtr_limit;
    uint16_t guest_cs;
    uint16_t guest_ss;
    uint16_t guest_ds;
    uint16_t guest_es;
    uint16_t guest_tr;
    uint16_t reserved1;
};

/* ================================================================
 * Build VMCS configuration for FreeBSD host deprivilege
 *
 * Sets up the VMCS to run the FreeBSD kernel as a guest with:
 * - EPT for memory isolation
 * - CR0/CR4 pinning for security feature enforcement
 * - MSR bitmap for SPEC_CTRL interception
 * - External interrupt and NMI exiting
 * - 64-bit guest mode
 *
 * The guest starts at the current CPU state (deprivilege in place),
 * so guest CR3/RIP/RSP must be captured from the current CPU.
 * ================================================================ */

/*@ requires \valid(config);
    assigns *config;
*/
/* Next VPID to allocate. VPID 0 is reserved (no VPID), start at 1.
 * Each vCPU gets a unique VPID for TLB isolation (REQ-0341). */
static uint16_t g_next_vpid = 1U;

static void fbvbs_vmcs_build_host_config(
    struct fbvbs_vmcs_config *config,
    uint64_t pinned_cr0_mask,
    uint64_t pinned_cr0_value,
    uint64_t pinned_cr4_mask,
    uint64_t pinned_cr4_value,
    uint64_t ept_pml4_phys)
{
    *config = (struct fbvbs_vmcs_config){0};

    /* Allocate unique VPID (REQ-0341).
     * VPID 0 is reserved (disables VPID tagging).
     * Saturate at 0xFFFF — 65534 vCPUs is far beyond spec limit. */
    if (g_next_vpid == 0U) {
        g_next_vpid = 1U;  /* Recover from hypothetical wraparound */
    }
    config->vpid = g_next_vpid;
    if (g_next_vpid < 0xFFFFU) {
        g_next_vpid = (uint16_t)(g_next_vpid + 1U);
    }

    /* ---- Pin-based VM execution controls ---- */
    config->pin_based_controls =
        PIN_EXTERNAL_INTERRUPT_EXITING |
        PIN_NMI_EXITING |
        PIN_VIRTUAL_NMIS;

    /* ---- Primary processor-based controls ---- */
    config->primary_proc_controls =
        PROC_HLT_EXITING |
        PROC_CR3_LOAD_EXITING |
        PROC_CR3_STORE_EXITING |
        PROC_MOV_DR_EXITING |
        PROC_USE_MSR_BITMAPS |
        PROC_ACTIVATE_SECONDARY;

    /* ---- Secondary processor-based controls ---- */
    config->secondary_proc_controls =
        PROC2_ENABLE_EPT |
        PROC2_ENABLE_VPID |
        PROC2_RDTSCP |
        PROC2_ENABLE_INVPCID |
        PROC2_ENABLE_XSAVES;

    /* ---- VM-exit controls (return to 64-bit hypervisor) ---- */
    config->exit_controls =
        EXIT_HOST_ADDR_SPACE_SIZE |
        EXIT_SAVE_IA32_EFER |
        EXIT_LOAD_IA32_EFER;

    /* ---- VM-entry controls (enter 64-bit guest) ---- */
    config->entry_controls =
        ENTRY_IA32E_MODE_GUEST |
        ENTRY_LOAD_IA32_EFER;

    /* ---- Exception bitmap ----
     * Intercept: #DB (1), #BP (3), #UD (6), #MC (18)
     * All others passed to guest */
    config->exception_bitmap =
        (1U << 1) |   /* #DB - debug */
        (1U << 3) |   /* #BP - breakpoint */
        (1U << 6) |   /* #UD - undefined opcode (for CPUID interception) */
        (1U << 18);   /* #MC - machine check */

    /* ---- CR0/CR4 guest-host mask ----
     * Bits set in the mask cause VM exits on guest CR writes.
     * We mask the pinned bits so the guest can't change them. */
    config->cr0_guest_host_mask = pinned_cr0_mask;
    config->cr4_guest_host_mask = pinned_cr4_mask;
    config->cr0_read_shadow = pinned_cr0_value;
    config->cr4_read_shadow = pinned_cr4_value;

    /* ---- EPT pointer ----
     * EPT memory type = WB (6), page walk length = 4 (3 << 3) */
    config->ept_pointer = (ept_pml4_phys & 0x000FFFFFFFFFF000ULL) |
                          (3ULL << 3) |  /* 4-level page walk */
                          6ULL;           /* WB memory type */

    /* Host segment selectors (flat 64-bit model) */
    config->host_cs = 0x08U;
    config->host_ss = 0x10U;
    config->host_ds = 0x00U;
    config->host_es = 0x00U;
    config->host_fs = 0x00U;
    config->host_gs = 0x00U;
    config->host_tr = 0x18U;  /* TSS selector */

    /* Guest starts in 64-bit mode with interrupts enabled */
    config->guest_rflags = 0x202ULL;  /* IF=1, reserved bit 1 */

    /* Guest segment selectors (FreeBSD kernel: flat model) */
    config->guest_cs = 0x08U;
    config->guest_ss = 0x10U;
    config->guest_ds = 0x10U;
    config->guest_es = 0x10U;
    config->guest_tr = 0x18U;
}

/* ================================================================
 * Apply VMCS configuration via VMWRITE
 *
 * PRODUCTION NOTE: Each field must be written via the VMWRITE
 * instruction. This function documents the complete write sequence.
 * Assembly implementation should call VMWRITE for each field
 * and check for errors (CF=1 or ZF=1 after VMWRITE).
 *
 * int vmwrite_all(const struct fbvbs_vmcs_config *config):
 *   - VMCLEAR the VMCS page first
 *   - VMPTRLD to make it the active VMCS
 *   - VMWRITE each field
 *   - Return 0 on success, -1 on VMWRITE failure
 * ================================================================ */

/* IA32_VMX_BASIC MSR — bits [30:0] contain the VMCS revision ID */
#define MSR_IA32_VMX_BASIC 0x480U

/* Track the allocated VMCS page physical address for cleanup */
static uint64_t g_vmcs_page_phys;

/*@ requires \valid_read(config);
    assigns g_vmcs_page_phys;
    ensures \result == 0 || \result == -1;
*/
int fbvbs_vmcs_apply(const struct fbvbs_vmcs_config *config)
{
    uint64_t vmcs_phys;
    uint32_t vmcs_revision;
#ifndef __FRAMAC__
    volatile uint32_t *vmcs_virt;
#endif

    if (config == NULL) {
        return -1;
    }

    /* 1. Allocate a 4KB-aligned VMCS page (already zeroed by allocator) */
    vmcs_phys = fbvbs_page_alloc();
    if (vmcs_phys == 0U) {
        return -1;  /* No physical memory available */
    }

    /* 2. Write VMCS revision ID to first 31 bits of the page.
     *    The revision ID is in IA32_VMX_BASIC[30:0]. */
    vmcs_revision = (uint32_t)(fbvbs_asm_rdmsr(MSR_IA32_VMX_BASIC) & 0x7FFFFFFFU);

#ifndef __FRAMAC__
    /* Identity-mapped: physical address == virtual address */
    vmcs_virt = (volatile uint32_t *)(uintptr_t)vmcs_phys;
    *vmcs_virt = vmcs_revision;
#endif

    /* 3. VMCLEAR the page */
    if (fbvbs_asm_vmclear(vmcs_phys) != 0) {
        (void)fbvbs_page_free(vmcs_phys);
        return -1;
    }

    /* 4. VMPTRLD to make it the active VMCS */
    if (fbvbs_asm_vmptrld(vmcs_phys) != 0) {
        (void)fbvbs_page_free(vmcs_phys);
        return -1;
    }

    g_vmcs_page_phys = vmcs_phys;

    /* 5. VMWRITE all control fields.
     *    Any VMWRITE failure → abort (fail-closed). */

    /* Control fields */
    if (fbvbs_asm_vmwrite(VMCS_VPID, config->vpid) != 0) { return -1; }
    if (fbvbs_asm_vmwrite(VMCS_PIN_BASED_CONTROLS, config->pin_based_controls) != 0) { return -1; }
    if (fbvbs_asm_vmwrite(VMCS_PRIMARY_PROC_CONTROLS, config->primary_proc_controls) != 0) { return -1; }
    if (fbvbs_asm_vmwrite(VMCS_SECONDARY_PROC_CONTROLS, config->secondary_proc_controls) != 0) { return -1; }
    if (fbvbs_asm_vmwrite(VMCS_EXIT_CONTROLS, config->exit_controls) != 0) { return -1; }
    if (fbvbs_asm_vmwrite(VMCS_ENTRY_CONTROLS, config->entry_controls) != 0) { return -1; }
    if (fbvbs_asm_vmwrite(VMCS_EXCEPTION_BITMAP, config->exception_bitmap) != 0) { return -1; }

    /* CR mask/shadow */
    if (fbvbs_asm_vmwrite(VMCS_CR0_GUEST_HOST_MASK, config->cr0_guest_host_mask) != 0) { return -1; }
    if (fbvbs_asm_vmwrite(VMCS_CR4_GUEST_HOST_MASK, config->cr4_guest_host_mask) != 0) { return -1; }
    if (fbvbs_asm_vmwrite(VMCS_CR0_READ_SHADOW, config->cr0_read_shadow) != 0) { return -1; }
    if (fbvbs_asm_vmwrite(VMCS_CR4_READ_SHADOW, config->cr4_read_shadow) != 0) { return -1; }

    /* EPT pointer */
    if (fbvbs_asm_vmwrite(VMCS_EPT_POINTER, config->ept_pointer) != 0) { return -1; }

    /* Host state */
    if (fbvbs_asm_vmwrite(VMCS_HOST_CR0, config->host_cr0) != 0) { return -1; }
    if (fbvbs_asm_vmwrite(VMCS_HOST_CR3, config->host_cr3) != 0) { return -1; }
    if (fbvbs_asm_vmwrite(VMCS_HOST_CR4, config->host_cr4) != 0) { return -1; }
    if (fbvbs_asm_vmwrite(VMCS_HOST_RSP, config->host_rsp) != 0) { return -1; }
    if (fbvbs_asm_vmwrite(VMCS_HOST_RIP, config->host_rip) != 0) { return -1; }
    if (fbvbs_asm_vmwrite(VMCS_HOST_IA32_EFER, config->host_efer) != 0) { return -1; }
    if (fbvbs_asm_vmwrite(VMCS_HOST_GDTR_BASE, config->host_gdtr_base) != 0) { return -1; }
    if (fbvbs_asm_vmwrite(VMCS_HOST_IDTR_BASE, config->host_idtr_base) != 0) { return -1; }
    if (fbvbs_asm_vmwrite(VMCS_HOST_TR_BASE, config->host_tr_base) != 0) { return -1; }

    /* Host segment selectors */
    if (fbvbs_asm_vmwrite(VMCS_HOST_CS_SELECTOR, config->host_cs) != 0) { return -1; }
    if (fbvbs_asm_vmwrite(VMCS_HOST_SS_SELECTOR, config->host_ss) != 0) { return -1; }
    if (fbvbs_asm_vmwrite(VMCS_HOST_DS_SELECTOR, config->host_ds) != 0) { return -1; }
    if (fbvbs_asm_vmwrite(VMCS_HOST_ES_SELECTOR, config->host_es) != 0) { return -1; }
    if (fbvbs_asm_vmwrite(VMCS_HOST_FS_SELECTOR, config->host_fs) != 0) { return -1; }
    if (fbvbs_asm_vmwrite(VMCS_HOST_GS_SELECTOR, config->host_gs) != 0) { return -1; }
    if (fbvbs_asm_vmwrite(VMCS_HOST_TR_SELECTOR, config->host_tr) != 0) { return -1; }

    /* Guest state */
    if (fbvbs_asm_vmwrite(VMCS_GUEST_CR0, config->guest_cr0) != 0) { return -1; }
    if (fbvbs_asm_vmwrite(VMCS_GUEST_CR3, config->guest_cr3) != 0) { return -1; }
    if (fbvbs_asm_vmwrite(VMCS_GUEST_CR4, config->guest_cr4) != 0) { return -1; }
    if (fbvbs_asm_vmwrite(VMCS_GUEST_RSP, config->guest_rsp) != 0) { return -1; }
    if (fbvbs_asm_vmwrite(VMCS_GUEST_RIP, config->guest_rip) != 0) { return -1; }
    if (fbvbs_asm_vmwrite(VMCS_GUEST_RFLAGS, config->guest_rflags) != 0) { return -1; }
    if (fbvbs_asm_vmwrite(VMCS_GUEST_IA32_EFER, config->guest_efer) != 0) { return -1; }

    /* Guest segment selectors */
    if (fbvbs_asm_vmwrite(VMCS_GUEST_CS_SELECTOR, config->guest_cs) != 0) { return -1; }
    if (fbvbs_asm_vmwrite(VMCS_GUEST_SS_SELECTOR, config->guest_ss) != 0) { return -1; }
    if (fbvbs_asm_vmwrite(VMCS_GUEST_DS_SELECTOR, config->guest_ds) != 0) { return -1; }
    if (fbvbs_asm_vmwrite(VMCS_GUEST_ES_SELECTOR, config->guest_es) != 0) { return -1; }
    if (fbvbs_asm_vmwrite(VMCS_GUEST_TR_SELECTOR, config->guest_tr) != 0) { return -1; }

    /* Guest descriptor table bases/limits */
    if (fbvbs_asm_vmwrite(VMCS_GUEST_GDTR_BASE, config->guest_gdtr_base) != 0) { return -1; }
    if (fbvbs_asm_vmwrite(VMCS_GUEST_GDTR_LIMIT, config->guest_gdtr_limit) != 0) { return -1; }
    if (fbvbs_asm_vmwrite(VMCS_GUEST_IDTR_BASE, config->guest_idtr_base) != 0) { return -1; }
    if (fbvbs_asm_vmwrite(VMCS_GUEST_IDTR_LIMIT, config->guest_idtr_limit) != 0) { return -1; }

    /* Guest activity and interruptibility (normal execution, no blocking) */
    if (fbvbs_asm_vmwrite(VMCS_GUEST_ACTIVITY_STATE, 0U) != 0) { return -1; }
    if (fbvbs_asm_vmwrite(VMCS_GUEST_INTERRUPTIBILITY, 0U) != 0) { return -1; }

    /* Guest DR7 (debug registers — default value) */
    if (fbvbs_asm_vmwrite(VMCS_GUEST_DR7, 0x400ULL) != 0) { return -1; }

    /* VMCS link pointer — required to be FFFFFFFF_FFFFFFFF when
     * VMCS shadowing is not used */
    if (fbvbs_asm_vmwrite(0x2800U, UINT64_MAX) != 0) { return -1; }

    return 0;
}

/* ================================================================
 * FreeBSD host deprivilege entry point
 *
 * Called during hypervisor initialization to transition the
 * FreeBSD kernel from ring 0 to VMX non-root operation.
 *
 * The deprivilege sequence:
 * 1. Capture current CPU state (CR0/CR3/CR4/RIP/RSP/GDTR/IDTR)
 * 2. Build VMCS with captured state as guest state
 * 3. Set hypervisor VM-exit handler as HOST_RIP
 * 4. VMLAUNCH → FreeBSD resumes as guest
 * 5. On VM exit: hypervisor handles exit, VMRESUME
 * ================================================================ */

/*@ requires \valid(state);
    assigns *state;
    ensures \result == 0 || \result == -1;
*/
int fbvbs_deprivilege_host(struct fbvbs_hypervisor_state *state)
{
    struct fbvbs_vmcs_config config;

    if (state == NULL) {
        return -1;
    }

    /* Build VMCS configuration */
    fbvbs_vmcs_build_host_config(
        &config,
        state->pinned_cr0_mask,
        state->pinned_cr0_value,
        state->pinned_cr4_mask,
        state->pinned_cr4_value,
        0ULL  /* EPT PML4 — requires EPT page table construction */
    );

    /* PRODUCTION NOTE: Before VMLAUNCH:
     *
     * 1. Capture current CPU state into guest fields:
     *    - Read CR0 → config.guest_cr0
     *    - Read CR3 → config.guest_cr3
     *    - Read CR4 → config.guest_cr4
     *    - Read EFER MSR → config.guest_efer
     *    - Read GDTR → config.guest_gdtr_base/limit
     *    - Read IDTR → config.guest_idtr_base/limit
     *    - Set guest RIP to return address (where FreeBSD resumes)
     *    - Set guest RSP to current stack pointer
     *
     * 2. Set host state:
     *    - config.host_cr0/cr3/cr4 = hypervisor CR values
     *    - config.host_rip = &vmexit_handler (assembly)
     *    - config.host_rsp = hypervisor stack top
     *    - config.host_efer = hypervisor EFER
     *
     * 3. Build EPT mapping of FreeBSD's physical memory
     *
     * 4. Apply VMCS and VMLAUNCH
     *
     * All of this requires assembly support code. */

    if (fbvbs_vmcs_apply(&config) != 0) {
        return -1;
    }

    /* VMLAUNCH would be here (assembly) */

    return -1;  /* Fail-closed: VMLAUNCH not implemented */
}
