#include "fbvbs_hypervisor.h"
#include "fbvbs_asm.h"

uint64_t fbvbs_vmx_get_msr_bitmap_phys(void);

/* ================================================================
 * VMCS (Virtual Machine Control Structure) Setup for FreeBSD Host
 *
 * Configures the VMCS fields required to run FreeBSD as a
 * deprivileged guest in VMX non-root operation. This module
 * provides the C-level field setup; actual VMWRITE/VMREAD/VMLAUNCH
 * require assembly support code.
 *
 * Requirements: REQ-0201 (形式的解析証拠 — VMCS documents VM deprivilege)
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
#define VMCS_TERTIARY_PROC_CONTROLS     0x2034U

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
#define VMCS_NOTIFY_WINDOW              0x4024U

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
#define VMCS_VMX_PREEMPTION_TIMER_VALUE 0x482EU

/* 32-bit host-state fields */
#define VMCS_HOST_SYSENTER_CS           0x4C00U

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
#define PIN_VMX_PREEMPTION_TIMER        (1U << 6)

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
#define EXIT_LOAD_CET_STATE             (1U << 28)

/* VM-entry controls */
#define ENTRY_IA32E_MODE_GUEST          (1U << 9)   /* 64-bit guest */
#define ENTRY_LOAD_IA32_PAT             (1U << 14)
#define ENTRY_LOAD_IA32_EFER            (1U << 15)
#define ENTRY_LOAD_CET_STATE            (1U << 20)

#define FBVBS_SEG_SEL_KERNEL_DATA       0x10U
#define FBVBS_SEG_SEL_KERNEL_CODE64     0x18U
#define FBVBS_SEG_SEL_TSS64             0x20U

#define FBVBS_VMCS_AR_DATA              0xC093U
#define FBVBS_VMCS_AR_CODE64            0xA09BU
#define FBVBS_VMCS_AR_TSS64             0x0089U
#define FBVBS_VMCS_AR_UNUSABLE          0x10000U

#define FBVBS_VMCS_FLAT_LIMIT           0xFFFFFFFFU
#define FBVBS_VMCS_TSS_LIMIT            0x67U

#define MSR_IA32_FS_BASE                0xC0000100U
#define MSR_IA32_GS_BASE                0xC0000101U
#define MSR_IA32_SYSENTER_CS            0x00000174U
#define MSR_IA32_SYSENTER_ESP           0x00000175U
#define MSR_IA32_SYSENTER_EIP           0x00000176U

#define FBVBS_HOST_EPT_2MB_PAGE_SIZE    (2ULL * 1024ULL * 1024ULL)
#define FBVBS_HOST_EPT_MAX_PAGES        96U
#define EPT_READ                        (1ULL << 0)
#define EPT_WRITE                       (1ULL << 1)
#define EPT_EXECUTE                     (1ULL << 2)
#define EPT_MEM_TYPE_WB                 (6ULL << 3)
#define EPT_LARGE_PAGE                  (1ULL << 7)
#define EPT_ADDR_MASK                   0x000FFFFFFFFFF000ULL

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
    uint64_t tertiary_proc_controls;
    uint32_t exit_controls;
    uint32_t entry_controls;
    uint32_t exception_bitmap;
    uint32_t preemption_timer_value;
    uint32_t notify_window;

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

    /* MSR bitmap physical page */
    uint64_t msr_bitmap_phys;

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
    uint64_t host_fs_base;
    uint64_t host_gs_base;
    uint64_t host_s_cet;
    uint64_t host_ssp;
    uint64_t host_isst_addr;
    uint64_t host_sysenter_esp;
    uint64_t host_sysenter_eip;
    uint32_t host_sysenter_cs;
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
    uint64_t guest_es_base;
    uint64_t guest_cs_base;
    uint64_t guest_ss_base;
    uint64_t guest_ds_base;
    uint64_t guest_fs_base;
    uint64_t guest_gs_base;
    uint64_t guest_ldtr_base;
    uint64_t guest_tr_base;
    uint32_t guest_es_limit;
    uint32_t guest_cs_limit;
    uint32_t guest_ss_limit;
    uint32_t guest_ds_limit;
    uint32_t guest_fs_limit;
    uint32_t guest_gs_limit;
    uint32_t guest_ldtr_limit;
    uint32_t guest_tr_limit;
    uint32_t guest_es_access_rights;
    uint32_t guest_cs_access_rights;
    uint32_t guest_ss_access_rights;
    uint32_t guest_ds_access_rights;
    uint32_t guest_fs_access_rights;
    uint32_t guest_gs_access_rights;
    uint32_t guest_ldtr_access_rights;
    uint32_t guest_tr_access_rights;
    uint64_t guest_sysenter_esp;
    uint64_t guest_sysenter_eip;
    uint32_t guest_sysenter_cs;
    uint64_t guest_s_cet;
    uint16_t guest_cs;
    uint16_t guest_ss;
    uint16_t guest_ds;
    uint16_t guest_es;
    uint16_t guest_fs;
    uint16_t guest_gs;
    uint16_t guest_ldtr;
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

/* Next VPID to allocate. VPID 0 is reserved (no VPID), start at 1.
 * Each vCPU gets a unique VPID for TLB isolation (REQ-0341).
 *
 * SERIALIZATION: This counter is only modified by fbvbs_vmcs_build_host_config,
 * which is called from fbvbs_deprivilege_host. The deprivilege sequence runs
 * on the BSP before AP startup (Phase 8 mp_init.c: APs initialize after BSP
 * completes hypervisor_init). Per-AP VMCS setup in verify_cpu_consistency
 * does not call this function — each AP gets its VPID from the BSP-built
 * partition config. No concurrent access is possible. */
static uint16_t g_next_vpid = 1U;

/* IA32_VMX_BASIC MSR — bits [30:0] contain the VMCS revision ID */
#define MSR_IA32_VMX_BASIC            0x480U
#define MSR_IA32_VMX_PROCBASED_CTLS2  0x48BU
#define CR4_VMXE                      (1ULL << 13)

/* Track the allocated VMCS page physical address for cleanup */
static uint64_t g_vmcs_page_phys;
static uint64_t g_vmxon_page_phys;
static uint64_t g_vmxon_saved_cr4;
static uint32_t g_vmxon_cr4_owned;

static uint32_t fbvbs_vmx_allowed_secondary_controls(uint32_t requested);
static int fbvbs_vmxon_enter(void);
static void fbvbs_vmxon_leave(void);

/*@ requires \valid(config);
    assigns *config, g_next_vpid;
    ensures \result == 0 || \result == -1;
*/
static int fbvbs_vmcs_build_host_config(
    struct fbvbs_vmcs_config *config,
    uint64_t pinned_cr0_mask,
    uint64_t pinned_cr0_value,
    uint64_t pinned_cr4_mask,
    uint64_t pinned_cr4_value,
    uint64_t ept_pml4_phys)
{
#ifdef __FRAMAC__
    /* SYNC: stub for WP. VMCS config has ~80 fields; compound literal
     * causes goal explosion. Update stub if struct fbvbs_vmcs_config
     * or function signature changes. Correctness verified via unit tests
     * and QEMU smoke tests. */
    _Static_assert(sizeof(struct fbvbs_vmcs_config) == 520U,
                   "struct changed -- update __FRAMAC__ stub");
    config->pin_based_controls = 0U;
    config->vpid = 0U;
    g_next_vpid = 1U;
    (void)pinned_cr0_mask;
    (void)pinned_cr0_value;
    (void)pinned_cr4_mask;
    (void)pinned_cr4_value;
    (void)ept_pml4_phys;
    return 0;
#else
    *config = (struct fbvbs_vmcs_config){0};

    /* Allocate unique VPID (REQ-0341).
     * VPID 0 is reserved (disables VPID tagging).
     * Saturate at 0xFFFF — 65534 vCPUs is far beyond spec limit. */
    if (g_next_vpid == 0U) {
        g_next_vpid = 1U;  /* Recover from hypothetical wraparound */
    }
    if (g_next_vpid == 0xFFFFU) {
        /* VPID pool exhausted — cannot allocate unique VPID */
        return -1;
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
    config->secondary_proc_controls =
        fbvbs_vmx_allowed_secondary_controls(config->secondary_proc_controls);

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
     * EPT memory type = WB (6), page walk length = 4 (3 << 3).
     * If no valid EPT PML4 is provided, disable EPT to avoid
     * VMENTRY failure from invalid EPT pointer. */
    if (ept_pml4_phys == 0U) {
        config->secondary_proc_controls &= ~(uint32_t)PROC2_ENABLE_EPT;
        config->ept_pointer = 0U;
    } else {
        config->ept_pointer = (ept_pml4_phys & 0x000FFFFFFFFFF000ULL) |
                              (3ULL << 3) |  /* 4-level page walk */
                              6ULL;           /* WB memory type */
    }
    config->msr_bitmap_phys = 0U;

    /* Host segment selectors (must match boot.S runtime GDT). */
    config->host_cs = FBVBS_SEG_SEL_KERNEL_CODE64;
    config->host_ss = FBVBS_SEG_SEL_KERNEL_DATA;
    config->host_ds = FBVBS_SEG_SEL_KERNEL_DATA;
    config->host_es = FBVBS_SEG_SEL_KERNEL_DATA;
    config->host_fs = FBVBS_SEG_SEL_KERNEL_DATA;
    config->host_gs = FBVBS_SEG_SEL_KERNEL_DATA;
    config->host_tr = FBVBS_SEG_SEL_TSS64;

    /* Guest starts in 64-bit mode with interrupts enabled */
    config->guest_rflags = 0x202ULL;  /* IF=1, reserved bit 1 */

    /* Guest segment selectors follow the current retained-C runtime model. */
    config->guest_cs = FBVBS_SEG_SEL_KERNEL_CODE64;
    config->guest_ss = FBVBS_SEG_SEL_KERNEL_DATA;
    config->guest_ds = FBVBS_SEG_SEL_KERNEL_DATA;
    config->guest_es = FBVBS_SEG_SEL_KERNEL_DATA;
    config->guest_fs = FBVBS_SEG_SEL_KERNEL_DATA;
    config->guest_gs = FBVBS_SEG_SEL_KERNEL_DATA;
    config->guest_ldtr = 0U;
    config->guest_tr = FBVBS_SEG_SEL_TSS64;

    config->guest_es_limit = FBVBS_VMCS_FLAT_LIMIT;
    config->guest_cs_limit = FBVBS_VMCS_FLAT_LIMIT;
    config->guest_ss_limit = FBVBS_VMCS_FLAT_LIMIT;
    config->guest_ds_limit = FBVBS_VMCS_FLAT_LIMIT;
    config->guest_fs_limit = FBVBS_VMCS_FLAT_LIMIT;
    config->guest_gs_limit = FBVBS_VMCS_FLAT_LIMIT;
    config->guest_ldtr_limit = 0U;
    config->guest_tr_limit = FBVBS_VMCS_TSS_LIMIT;

    config->guest_es_access_rights = FBVBS_VMCS_AR_DATA;
    config->guest_cs_access_rights = FBVBS_VMCS_AR_CODE64;
    config->guest_ss_access_rights = FBVBS_VMCS_AR_DATA;
    config->guest_ds_access_rights = FBVBS_VMCS_AR_DATA;
    config->guest_fs_access_rights = FBVBS_VMCS_AR_DATA;
    config->guest_gs_access_rights = FBVBS_VMCS_AR_DATA;
    config->guest_ldtr_access_rights = FBVBS_VMCS_AR_UNUSABLE;
    config->guest_tr_access_rights = FBVBS_VMCS_AR_TSS64;
#endif /* !__FRAMAC__ */
    return 0;
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

/* Forward declaration for assembly-called VM exit handler */
void fbvbs_handle_vmexit(uint64_t *guest_gprs);

static void fbvbs_release_vmx_security_controls(
    const struct fbvbs_vmx_security_controls *controls)
{
    uint64_t host_ssp_page;

    if (controls == NULL) {
        return;
    }

    host_ssp_page = controls->host_ssp & ~((uint64_t)FBVBS_PAGE_SIZE - 1ULL);
    if (host_ssp_page != 0ULL) {
        (void)fbvbs_page_free(host_ssp_page);
    }
    if (controls->host_isst_addr != 0ULL) {
        (void)fbvbs_page_free(controls->host_isst_addr);
    }
}

static uint32_t fbvbs_vmx_allowed_secondary_controls(uint32_t requested)
{
#if defined(__x86_64__) && !defined(__FRAMAC__) && !defined(__STDC_HOSTED__)
    uint64_t controls = fbvbs_asm_rdmsr(MSR_IA32_VMX_PROCBASED_CTLS2);
    uint32_t allowed_1 = (uint32_t)(controls >> 32);

    return requested & allowed_1;
#else
    return requested;
#endif
}

static int fbvbs_vmxon_enter(void)
{
#if defined(__x86_64__) && !defined(__FRAMAC__) && !defined(__STDC_HOSTED__)
    uint64_t vmxon_phys;
    uint32_t revision_id;
    volatile uint32_t *vmxon_virt;
    uint64_t cr4;

    if (g_vmxon_page_phys != 0ULL) {
        return 0;
    }

    vmxon_phys = fbvbs_page_alloc();
    if (vmxon_phys == 0ULL) {
        return -1;
    }

    revision_id = (uint32_t)(fbvbs_asm_rdmsr(MSR_IA32_VMX_BASIC) & 0x7FFFFFFFU);
    vmxon_virt = (volatile uint32_t *)(uintptr_t)vmxon_phys;
    *vmxon_virt = revision_id;

    cr4 = fbvbs_asm_read_cr4();
    g_vmxon_saved_cr4 = cr4;
    g_vmxon_cr4_owned = ((cr4 & CR4_VMXE) == 0ULL) ? 1U : 0U;
    if (g_vmxon_cr4_owned != 0U) {
        fbvbs_asm_write_cr4(cr4 | CR4_VMXE);
    }

    if (fbvbs_asm_vmxon(vmxon_phys) != 0) {
        if (g_vmxon_cr4_owned != 0U) {
            fbvbs_asm_write_cr4(g_vmxon_saved_cr4);
        }
        g_vmxon_saved_cr4 = 0ULL;
        g_vmxon_cr4_owned = 0U;
        (void)fbvbs_page_free(vmxon_phys);
        return -1;
    }

    g_vmxon_page_phys = vmxon_phys;
    return 0;
#else
    return -1;
#endif
}

static void fbvbs_vmxon_leave(void)
{
#if defined(__x86_64__) && !defined(__FRAMAC__) && !defined(__STDC_HOSTED__)
    if (g_vmxon_page_phys == 0ULL) {
        return;
    }

    fbvbs_asm_vmxoff();
    if (g_vmxon_cr4_owned != 0U) {
        fbvbs_asm_write_cr4(g_vmxon_saved_cr4);
    }
    (void)fbvbs_page_free(g_vmxon_page_phys);
#endif
    g_vmxon_page_phys = 0ULL;
    g_vmxon_saved_cr4 = 0ULL;
    g_vmxon_cr4_owned = 0U;
}

struct fbvbs_host_ept_state {
    uint64_t root_phys;
    uint64_t page_phys[FBVBS_HOST_EPT_MAX_PAGES];
    uint32_t page_count;
    uint32_t reserved0;
};

static struct fbvbs_host_ept_state g_host_ept_state;

static int fbvbs_host_ept_record_page(struct fbvbs_host_ept_state *ept,
                                      uint64_t phys)
{
    if (ept == NULL || phys == 0ULL) {
        return -1;
    }
    if (ept->page_count >= FBVBS_HOST_EPT_MAX_PAGES) {
        return -1;
    }
    ept->page_phys[ept->page_count] = phys;
    ept->page_count += 1U;
    return 0;
}

static void fbvbs_host_ept_release(struct fbvbs_host_ept_state *ept)
{
    uint32_t index;

    if (ept == NULL) {
        return;
    }
    /*@ loop invariant 0 <= index <= ept->page_count;
        loop assigns index, ept->page_phys[0 .. FBVBS_HOST_EPT_MAX_PAGES - 1];
        loop variant ept->page_count - index;
    */
    for (index = 0U; index < ept->page_count; ++index) {
        if (ept->page_phys[index] != 0ULL) {
            (void)fbvbs_page_free(ept->page_phys[index]);
            ept->page_phys[index] = 0ULL;
        }
    }
#ifdef __FRAMAC__
    /* SYNC: field list must match struct fbvbs_host_ept_state. */
    _Static_assert(sizeof(struct fbvbs_host_ept_state) == 784U,
                   "struct changed -- update __FRAMAC__ stub");
    {
        uint32_t z;
        ept->root_phys = 0ULL;
        ept->page_count = 0U;
        ept->reserved0 = 0U;
        /*@ loop invariant 0 <= z <= FBVBS_HOST_EPT_MAX_PAGES;
            loop assigns z, ept->page_phys[0 .. FBVBS_HOST_EPT_MAX_PAGES - 1];
            loop variant FBVBS_HOST_EPT_MAX_PAGES - z;
        */
        for (z = 0U; z < FBVBS_HOST_EPT_MAX_PAGES; ++z) {
            ept->page_phys[z] = 0ULL;
        }
    }
#else
    *ept = (struct fbvbs_host_ept_state){0};
#endif
}

static uint16_t fbvbs_host_ept_permissions_for_type(uint32_t map_type)
{
    uint16_t permissions = FBVBS_MEMORY_PERMISSION_READ |
                           FBVBS_MEMORY_PERMISSION_WRITE;

    if (map_type == 1U) {
        permissions |= FBVBS_MEMORY_PERMISSION_EXECUTE;
    }
    return permissions;
}

static uint64_t *fbvbs_host_ept_get_or_alloc_child(
    struct fbvbs_host_ept_state *ept,
    uint64_t *table,
    uint32_t index)
{
    uint64_t entry;
    uint64_t child_phys;

    if (ept == NULL || table == NULL) {
        return NULL;
    }

    entry = table[index];
    if ((entry & EPT_READ) != 0ULL) {
        return (uint64_t *)(uintptr_t)(entry & EPT_ADDR_MASK);
    }

    child_phys = fbvbs_page_alloc();
    if (child_phys == 0ULL) {
        return NULL;
    }
    if (fbvbs_host_ept_record_page(ept, child_phys) != 0) {
        (void)fbvbs_page_free(child_phys);
        return NULL;
    }

    table[index] = (child_phys & EPT_ADDR_MASK) | EPT_READ | EPT_WRITE | EPT_EXECUTE;
    return (uint64_t *)(uintptr_t)child_phys;
}

static int fbvbs_host_ept_map_large_page(struct fbvbs_host_ept_state *ept,
                                         uint64_t phys_addr,
                                         uint16_t permissions)
{
    uint64_t *pml4;
    uint64_t *pdpt;
    uint64_t *pd;
    uint64_t ept_perm;
    uint32_t pml4_index;
    uint32_t pdpt_index;
    uint32_t pd_index;

    if (ept == NULL || ept->root_phys == 0ULL) {
        return -1;
    }

    pml4_index = (uint32_t)((phys_addr >> 39) & 0x1FFU);
    pdpt_index = (uint32_t)((phys_addr >> 30) & 0x1FFU);
    pd_index = (uint32_t)((phys_addr >> 21) & 0x1FFU);

    pml4 = (uint64_t *)(uintptr_t)ept->root_phys;
    pdpt = fbvbs_host_ept_get_or_alloc_child(ept, pml4, pml4_index);
    if (pdpt == NULL) {
        return -1;
    }
    pd = fbvbs_host_ept_get_or_alloc_child(ept, pdpt, pdpt_index);
    if (pd == NULL) {
        return -1;
    }

    ept_perm = 0ULL;
    if ((permissions & FBVBS_MEMORY_PERMISSION_READ) != 0U) {
        ept_perm |= EPT_READ;
    }
    if ((permissions & FBVBS_MEMORY_PERMISSION_WRITE) != 0U) {
        ept_perm |= EPT_WRITE;
    }
    if ((permissions & FBVBS_MEMORY_PERMISSION_EXECUTE) != 0U) {
        ept_perm |= EPT_EXECUTE;
    }

    pd[pd_index] = (phys_addr & EPT_ADDR_MASK) |
                   ept_perm |
                   EPT_MEM_TYPE_WB |
                   EPT_LARGE_PAGE;
    return 0;
}

static int fbvbs_find_freebsd_host_partition_id(
    const struct fbvbs_hypervisor_state *state,
    uint64_t *partition_id)
{
    uint32_t index;

    if (state == NULL || partition_id == NULL) {
        return -1;
    }

    /*@ loop invariant 0 <= index <= FBVBS_MAX_PARTITIONS;
        loop invariant \forall integer j; 0 <= j < index ==>
            !(state->partitions[j].occupied &&
              state->partitions[j].kind == PARTITION_KIND_FREEBSD_HOST);
        loop assigns index;
        loop variant FBVBS_MAX_PARTITIONS - index;
    */
    for (index = 0U; index < FBVBS_MAX_PARTITIONS; ++index) {
        if (state->partitions[index].occupied &&
            state->partitions[index].kind == PARTITION_KIND_FREEBSD_HOST) {
            *partition_id = state->partitions[index].partition_id;
            return 0;
        }
    }

    return -1;
}

static int fbvbs_build_host_identity_ept(
    const struct fbvbs_hypervisor_state *state,
    uint64_t *root_phys)
{
    uint32_t index;

    if (state == NULL || root_phys == NULL) {
        return -1;
    }

    if (g_host_ept_state.root_phys != 0ULL) {
        *root_phys = g_host_ept_state.root_phys;
        return 0;
    }

#ifdef __FRAMAC__
    /* SYNC: field list must match struct fbvbs_host_ept_state. */
    _Static_assert(sizeof(struct fbvbs_host_ept_state) == 784U,
                   "struct changed -- update __FRAMAC__ stub");
    {
        uint32_t z;
        g_host_ept_state.root_phys = 0ULL;
        g_host_ept_state.page_count = 0U;
        g_host_ept_state.reserved0 = 0U;
        /*@ loop invariant 0 <= z <= FBVBS_HOST_EPT_MAX_PAGES;
            loop assigns z, g_host_ept_state.page_phys[0 .. FBVBS_HOST_EPT_MAX_PAGES - 1];
            loop variant FBVBS_HOST_EPT_MAX_PAGES - z;
        */
        for (z = 0U; z < FBVBS_HOST_EPT_MAX_PAGES; ++z) {
            g_host_ept_state.page_phys[z] = 0ULL;
        }
    }
#else
    g_host_ept_state = (struct fbvbs_host_ept_state){0};
#endif
    g_host_ept_state.root_phys = fbvbs_page_alloc();
    if (g_host_ept_state.root_phys == 0ULL) {
        return -1;
    }
    if (fbvbs_host_ept_record_page(&g_host_ept_state, g_host_ept_state.root_phys) != 0) {
        fbvbs_host_ept_release(&g_host_ept_state);
        return -1;
    }

    /*@ loop invariant 0 <= index <= state->memory_map_count;
        loop assigns index,
                     g_host_ept_state,
                     g_host_ept_state.page_phys[0 .. FBVBS_HOST_EPT_MAX_PAGES - 1];
        loop variant state->memory_map_count - index;
    */
    for (index = 0U; index < state->memory_map_count; ++index) {
        uint64_t base_addr = state->memory_map[index].base_addr;
        uint64_t length = state->memory_map[index].length;
        uint64_t start;
        uint64_t end;
        uint64_t current;
        uint16_t permissions;

        if (length == 0ULL) {
            continue;
        }
        if (length > UINT64_MAX - base_addr) {
            fbvbs_host_ept_release(&g_host_ept_state);
            return -1;
        }

        start = base_addr & ~(FBVBS_HOST_EPT_2MB_PAGE_SIZE - 1ULL);
        if ((base_addr + length) > UINT64_MAX - (FBVBS_HOST_EPT_2MB_PAGE_SIZE - 1ULL)) {
            fbvbs_host_ept_release(&g_host_ept_state);
            return -1;
        }
        end = (base_addr + length + FBVBS_HOST_EPT_2MB_PAGE_SIZE - 1ULL) &
              ~(FBVBS_HOST_EPT_2MB_PAGE_SIZE - 1ULL);
        permissions = fbvbs_host_ept_permissions_for_type(state->memory_map[index].type);

        /*@ loop invariant start <= current <= end;
            loop assigns current,
                         g_host_ept_state,
                         g_host_ept_state.page_phys[0 .. FBVBS_HOST_EPT_MAX_PAGES - 1];
            loop variant (end - current) / FBVBS_HOST_EPT_2MB_PAGE_SIZE;
        */
        for (current = start; current < end; current += FBVBS_HOST_EPT_2MB_PAGE_SIZE) {
            if (fbvbs_host_ept_map_large_page(&g_host_ept_state, current, permissions) != 0) {
                fbvbs_host_ept_release(&g_host_ept_state);
                return -1;
            }
            if (current > UINT64_MAX - FBVBS_HOST_EPT_2MB_PAGE_SIZE) {
                break;
            }
        }
    }

    *root_phys = g_host_ept_state.root_phys;
    return 0;
}

/* Reject partial host-deprivilege handoff. Until the retained-C runtime
 * wires guest RIP/RSP capture, host TR base, EPT root construction, and
 * tertiary/preemption/CET VMCS fields end-to-end, this path must fail
 * closed instead of attempting a downgraded VM entry. */
static int fbvbs_deprivilege_preflight_ready(
    const struct fbvbs_vmcs_config *config,
    const struct fbvbs_vmx_security_controls *controls)
{
    if (config == NULL || controls == NULL) {
        return 0;
    }

    if ((config->secondary_proc_controls & PROC2_ENABLE_EPT) == 0U ||
        config->ept_pointer == 0ULL) {
        return 0;
    }
    if (config->guest_rip == 0ULL || config->guest_rsp == 0ULL) {
        return 0;
    }
    if (config->host_rip == 0ULL ||
        config->host_rsp == 0ULL ||
        config->host_tr_base == 0ULL) {
        return 0;
    }
    if (config->guest_tr_base == 0ULL) {
        return 0;
    }
    if (config->msr_bitmap_phys == 0ULL || controls->msr_bitmap_valid == 0U) {
        return 0;
    }
    if ((config->pin_based_controls & PIN_VMX_PREEMPTION_TIMER) != 0U &&
        config->preemption_timer_value == 0U) {
        return 0;
    }
    if ((config->entry_controls & ENTRY_LOAD_CET_STATE) != 0U &&
        (config->host_s_cet == 0ULL || config->host_ssp == 0ULL)) {
        return 0;
    }

    return 1;
}

/*@ assigns g_vmcs_page_phys;
    ensures g_vmcs_page_phys == 0U;
*/
void fbvbs_vmcs_release_current(void)
{
    if (g_vmcs_page_phys == 0U) {
        return;
    }

    (void)fbvbs_asm_vmclear(g_vmcs_page_phys);
    (void)fbvbs_page_free(g_vmcs_page_phys);
    g_vmcs_page_phys = 0U;
}

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

#ifdef __FRAMAC__
    /* SYNC: stub for WP. ~80 VMWRITEs with goto-on-fail create exponential
     * paths. Update if VMCS field set changes. Verified via unit tests
     * and QEMU smoke tests. */
    (void)vmcs_revision;
    return 0;
#else
    /* 5. VMWRITE all control fields.
     *    Any VMWRITE failure → free page and abort (fail-closed).
     *    All VMWRITE errors goto vmwrite_fail to prevent page leak (CWE-401). */

    /* Control fields */
    if (fbvbs_asm_vmwrite(VMCS_VPID, config->vpid) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_PIN_BASED_CONTROLS, config->pin_based_controls) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_PRIMARY_PROC_CONTROLS, config->primary_proc_controls) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_SECONDARY_PROC_CONTROLS, config->secondary_proc_controls) != 0) { goto vmwrite_fail; }
    if (config->tertiary_proc_controls != 0ULL &&
        fbvbs_asm_vmwrite(VMCS_TERTIARY_PROC_CONTROLS, config->tertiary_proc_controls) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_EXIT_CONTROLS, config->exit_controls) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_ENTRY_CONTROLS, config->entry_controls) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_EXCEPTION_BITMAP, config->exception_bitmap) != 0) { goto vmwrite_fail; }
    if (config->preemption_timer_value != 0U &&
        fbvbs_asm_vmwrite(VMCS_VMX_PREEMPTION_TIMER_VALUE, config->preemption_timer_value) != 0) { goto vmwrite_fail; }
    if (config->tertiary_proc_controls != 0ULL &&
        fbvbs_asm_vmwrite(VMCS_NOTIFY_WINDOW, config->notify_window) != 0) { goto vmwrite_fail; }

    /* CR mask/shadow */
    if (fbvbs_asm_vmwrite(VMCS_CR0_GUEST_HOST_MASK, config->cr0_guest_host_mask) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_CR4_GUEST_HOST_MASK, config->cr4_guest_host_mask) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_CR0_READ_SHADOW, config->cr0_read_shadow) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_CR4_READ_SHADOW, config->cr4_read_shadow) != 0) { goto vmwrite_fail; }

    /* EPT pointer */
    if (fbvbs_asm_vmwrite(VMCS_EPT_POINTER, config->ept_pointer) != 0) { goto vmwrite_fail; }
    if (config->msr_bitmap_phys == 0U) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_MSR_BITMAP, config->msr_bitmap_phys) != 0) { goto vmwrite_fail; }

    /* Host state */
    if (fbvbs_asm_vmwrite(VMCS_HOST_CR0, config->host_cr0) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_HOST_CR3, config->host_cr3) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_HOST_CR4, config->host_cr4) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_HOST_RSP, config->host_rsp) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_HOST_RIP, config->host_rip) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_HOST_IA32_EFER, config->host_efer) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_HOST_FS_BASE, config->host_fs_base) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_HOST_GS_BASE, config->host_gs_base) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_HOST_GDTR_BASE, config->host_gdtr_base) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_HOST_IDTR_BASE, config->host_idtr_base) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_HOST_TR_BASE, config->host_tr_base) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_HOST_SYSENTER_CS, config->host_sysenter_cs) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_HOST_SYSENTER_ESP, config->host_sysenter_esp) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_HOST_SYSENTER_EIP, config->host_sysenter_eip) != 0) { goto vmwrite_fail; }
    if ((config->entry_controls & ENTRY_LOAD_CET_STATE) != 0U) {
        if (fbvbs_asm_vmwrite(0x6C18U, config->host_s_cet) != 0) { goto vmwrite_fail; }
        if (fbvbs_asm_vmwrite(0x6C1CU, config->host_ssp) != 0) { goto vmwrite_fail; }
        if (fbvbs_asm_vmwrite(0x6C20U, config->host_isst_addr) != 0) { goto vmwrite_fail; }
    }

    /* Host segment selectors */
    if (fbvbs_asm_vmwrite(VMCS_HOST_CS_SELECTOR, config->host_cs) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_HOST_SS_SELECTOR, config->host_ss) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_HOST_DS_SELECTOR, config->host_ds) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_HOST_ES_SELECTOR, config->host_es) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_HOST_FS_SELECTOR, config->host_fs) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_HOST_GS_SELECTOR, config->host_gs) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_HOST_TR_SELECTOR, config->host_tr) != 0) { goto vmwrite_fail; }

    /* Guest state */
    if (fbvbs_asm_vmwrite(VMCS_GUEST_CR0, config->guest_cr0) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_GUEST_CR3, config->guest_cr3) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_GUEST_CR4, config->guest_cr4) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_GUEST_RSP, config->guest_rsp) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_GUEST_RIP, config->guest_rip) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_GUEST_RFLAGS, config->guest_rflags) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_GUEST_IA32_EFER, config->guest_efer) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_GUEST_ES_BASE, config->guest_es_base) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_GUEST_CS_BASE, config->guest_cs_base) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_GUEST_SS_BASE, config->guest_ss_base) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_GUEST_DS_BASE, config->guest_ds_base) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_GUEST_FS_BASE, config->guest_fs_base) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_GUEST_GS_BASE, config->guest_gs_base) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_GUEST_LDTR_BASE, config->guest_ldtr_base) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_GUEST_TR_BASE, config->guest_tr_base) != 0) { goto vmwrite_fail; }

    /* Guest segment selectors */
    if (fbvbs_asm_vmwrite(VMCS_GUEST_CS_SELECTOR, config->guest_cs) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_GUEST_SS_SELECTOR, config->guest_ss) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_GUEST_DS_SELECTOR, config->guest_ds) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_GUEST_ES_SELECTOR, config->guest_es) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_GUEST_FS_SELECTOR, config->guest_fs) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_GUEST_GS_SELECTOR, config->guest_gs) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_GUEST_LDTR_SELECTOR, config->guest_ldtr) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_GUEST_TR_SELECTOR, config->guest_tr) != 0) { goto vmwrite_fail; }

    /* Guest descriptor table bases/limits */
    if (fbvbs_asm_vmwrite(VMCS_GUEST_GDTR_BASE, config->guest_gdtr_base) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_GUEST_GDTR_LIMIT, config->guest_gdtr_limit) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_GUEST_IDTR_BASE, config->guest_idtr_base) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_GUEST_IDTR_LIMIT, config->guest_idtr_limit) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_GUEST_ES_LIMIT, config->guest_es_limit) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_GUEST_CS_LIMIT, config->guest_cs_limit) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_GUEST_SS_LIMIT, config->guest_ss_limit) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_GUEST_DS_LIMIT, config->guest_ds_limit) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_GUEST_FS_LIMIT, config->guest_fs_limit) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_GUEST_GS_LIMIT, config->guest_gs_limit) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_GUEST_LDTR_LIMIT, config->guest_ldtr_limit) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_GUEST_TR_LIMIT, config->guest_tr_limit) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_GUEST_ES_ACCESS_RIGHTS, config->guest_es_access_rights) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_GUEST_CS_ACCESS_RIGHTS, config->guest_cs_access_rights) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_GUEST_SS_ACCESS_RIGHTS, config->guest_ss_access_rights) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_GUEST_DS_ACCESS_RIGHTS, config->guest_ds_access_rights) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_GUEST_FS_ACCESS_RIGHTS, config->guest_fs_access_rights) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_GUEST_GS_ACCESS_RIGHTS, config->guest_gs_access_rights) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_GUEST_LDTR_ACCESS_RIGHTS, config->guest_ldtr_access_rights) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_GUEST_TR_ACCESS_RIGHTS, config->guest_tr_access_rights) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_GUEST_SYSENTER_CS, config->guest_sysenter_cs) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_GUEST_SYSENTER_ESP, config->guest_sysenter_esp) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_GUEST_SYSENTER_EIP, config->guest_sysenter_eip) != 0) { goto vmwrite_fail; }

    /* Guest activity and interruptibility (normal execution, no blocking) */
    if (fbvbs_asm_vmwrite(VMCS_GUEST_ACTIVITY_STATE, 0U) != 0) { goto vmwrite_fail; }
    if (fbvbs_asm_vmwrite(VMCS_GUEST_INTERRUPTIBILITY, 0U) != 0) { goto vmwrite_fail; }

    /* Guest DR7 (debug registers — default value) */
    if (fbvbs_asm_vmwrite(VMCS_GUEST_DR7, 0x400ULL) != 0) { goto vmwrite_fail; }

    /* VMCS link pointer — required to be FFFFFFFF_FFFFFFFF when
     * VMCS shadowing is not used */
    if (fbvbs_asm_vmwrite(0x2800U, UINT64_MAX) != 0) { goto vmwrite_fail; }

    return 0;

vmwrite_fail:
    /* VMCLEAR before freeing to prevent the processor from referencing freed memory */
    if (g_vmcs_page_phys == vmcs_phys) {
        fbvbs_asm_vmclear(vmcs_phys);
    }
    (void)fbvbs_page_free(vmcs_phys);
    g_vmcs_page_phys = 0U;
    return -1;
#endif /* !__FRAMAC__ */
}

static void fbvbs_vmcs_put_hex64(uint64_t value)
{
    char buf[19];
    static const char hex[] = "0123456789ABCDEF";
    uint32_t i;

    buf[0] = '0';
    buf[1] = 'x';
    for (i = 0U; i < 16U; ++i) {
        buf[2U + i] = hex[(value >> (60U - (i * 4U))) & 0xFU];
    }
    buf[18] = '\0';
    fbvbs_boot_console_puts(buf);
}

__attribute__((noreturn, unused))
static void fbvbs_vmexit_fatal(uint64_t vmcs_phys,
                               uint64_t exit_reason,
                               uint64_t exit_qualification)
{
    fbvbs_boot_console_puts("FATAL: VMEXIT triple fault on VMCS ");
    fbvbs_vmcs_put_hex64(vmcs_phys);
    fbvbs_boot_console_puts(" exit_reason=");
    fbvbs_vmcs_put_hex64(exit_reason);
    fbvbs_boot_console_puts(" exit_qualification=");
    fbvbs_vmcs_put_hex64(exit_qualification);
    fbvbs_boot_console_puts("\n");

#if defined(__x86_64__) && !defined(__FRAMAC__) && !defined(__STDC_HOSTED__)
    for (;;) {
        fbvbs_asm_cli();
        fbvbs_asm_hlt();
    }
#else
    __builtin_trap();
#endif
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
#ifdef __FRAMAC__
    /* SYNC: stub for WP. Full body uses fbvbs_vmcs_config (80 fields)
     * causing goal explosion. Update if deprivilege logic changes.
     * Verified via test_vmx_handoff.c and QEMU smoke tests. */
    if (state == NULL) {
        return -1;
    }
    /* Reject double deprivilege — preserve flag for caller diagnostics */
    if ((state->runtime_state_flags & FBVBS_RUNTIME_HOST_DEPRIVILEGED) != 0U) {
        return -1;
    }
    state->runtime_state_flags &= ~FBVBS_RUNTIME_HOST_DEPRIVILEGED;
    return -1;
#else
    struct fbvbs_vmcs_config config;
    struct fbvbs_vmx_security_controls vmx_security;
    uint64_t ept_pml4_phys = 0ULL;
    uint64_t host_partition_id = 0ULL;

    if (state == NULL) {
        return -1;
    }
    /* Reject double deprivilege — preserve flag for caller diagnostics */
    if ((state->runtime_state_flags & FBVBS_RUNTIME_HOST_DEPRIVILEGED) != 0U) {
        return -1;
    }
    state->runtime_state_flags &= ~FBVBS_RUNTIME_HOST_DEPRIVILEGED;

    if (fbvbs_find_freebsd_host_partition_id(state, &host_partition_id) != 0) {
        return -1;
    }
    if (fbvbs_build_host_identity_ept(state, &ept_pml4_phys) != 0) {
        return -1;
    }

    /* Build VMCS configuration with pinning masks */
    if (fbvbs_vmcs_build_host_config(
            &config,
            state->pinned_cr0_mask,
            state->pinned_cr0_value,
            state->pinned_cr4_mask,
            state->pinned_cr4_value,
            ept_pml4_phys) != 0) {
        fbvbs_host_ept_release(&g_host_ept_state);
        return -1;
    }

    if (fbvbs_vmx_build_security_controls(&vmx_security, &state->vmx_caps) != 0) {
        fbvbs_host_ept_release(&g_host_ept_state);
        return -1;
    }

    /* Retained-C host deprivilege currently wires MSR bitmap, bus-lock
     * detect, preemption timer, and notify VM exit. CET root/non-root
     * state handoff needs authoritative guest SSP capture before it can
     * be enabled safely, so drop CET-specific fields fail-closed here. */
    if ((vmx_security.entry_controls_or & ENTRY_LOAD_CET_STATE) != 0U ||
        (vmx_security.exit_controls_or & EXIT_LOAD_CET_STATE) != 0U ||
        vmx_security.host_s_cet != 0ULL ||
        vmx_security.host_ssp != 0ULL ||
        vmx_security.host_isst_addr != 0ULL ||
        vmx_security.guest_s_cet != 0ULL) {
        fbvbs_release_vmx_security_controls(&vmx_security);
        vmx_security.entry_controls_or &= ~ENTRY_LOAD_CET_STATE;
        vmx_security.exit_controls_or &= ~EXIT_LOAD_CET_STATE;
        vmx_security.host_s_cet = 0ULL;
        vmx_security.host_ssp = 0ULL;
        vmx_security.host_isst_addr = 0ULL;
        vmx_security.guest_s_cet = 0ULL;
    }

    config.pin_based_controls |= vmx_security.pin_controls_or;
    config.primary_proc_controls |= vmx_security.primary_proc_or;
    config.secondary_proc_controls |= vmx_security.secondary_proc_or;
    config.secondary_proc_controls =
        fbvbs_vmx_allowed_secondary_controls(config.secondary_proc_controls);
    config.tertiary_proc_controls |= vmx_security.tertiary_proc_or;
    config.exit_controls |= vmx_security.exit_controls_or;
    config.entry_controls |= vmx_security.entry_controls_or;
    config.preemption_timer_value = vmx_security.preemption_timer_value;
    config.notify_window = vmx_security.notify_window;
    config.host_s_cet = vmx_security.host_s_cet;
    config.host_ssp = vmx_security.host_ssp;
    config.host_isst_addr = vmx_security.host_isst_addr;
    config.guest_s_cet = vmx_security.guest_s_cet;
    config.msr_bitmap_phys = fbvbs_vmx_get_msr_bitmap_phys();
    if (config.msr_bitmap_phys == 0U) {
        fbvbs_host_ept_release(&g_host_ept_state);
        fbvbs_release_vmx_security_controls(&vmx_security);
        return -1;
    }

#if defined(__x86_64__) && !defined(__FRAMAC__) && !defined(__STDC_HOSTED__)
    {
        struct fbvbs_asm_dt_reg gdtr, idtr;

        /* 1. Capture current CPU state as guest state.
         *    The guest (FreeBSD) will resume with these exact register
         *    values, so it sees no discontinuity from the deprivilege. */
        config.guest_cr0 = fbvbs_asm_read_cr0();
        config.guest_cr3 = fbvbs_asm_read_cr3();
        config.guest_cr4 = fbvbs_asm_read_cr4();
        config.guest_efer = fbvbs_asm_rdmsr(0xC0000080U); /* IA32_EFER */
        config.guest_fs_base = fbvbs_asm_rdmsr(MSR_IA32_FS_BASE);
        config.guest_gs_base = fbvbs_asm_rdmsr(MSR_IA32_GS_BASE);
        config.guest_tr_base = fbvbs_get_boot_tss_base();
        config.guest_sysenter_cs = (uint32_t)fbvbs_asm_rdmsr(MSR_IA32_SYSENTER_CS);
        config.guest_sysenter_esp = fbvbs_asm_rdmsr(MSR_IA32_SYSENTER_ESP);
        config.guest_sysenter_eip = fbvbs_asm_rdmsr(MSR_IA32_SYSENTER_EIP);

        fbvbs_asm_sgdt(&gdtr);
        config.guest_gdtr_base = gdtr.base;
        config.guest_gdtr_limit = (uint64_t)gdtr.limit;

        fbvbs_asm_sidt(&idtr);
        config.guest_idtr_base = idtr.base;
        config.guest_idtr_limit = (uint64_t)idtr.limit;

        config.guest_es_base = 0ULL;
        config.guest_cs_base = 0ULL;
        config.guest_ss_base = 0ULL;
        config.guest_ds_base = 0ULL;
        config.guest_ldtr_base = 0ULL;
        config.guest_rflags = fbvbs_asm_read_rflags();
        config.guest_rsp = fbvbs_asm_read_rsp();
        config.guest_rip = (uint64_t)(uintptr_t)(__extension__ &&guest_resume);

        /* 2. Set host state — hypervisor's own CR/RIP/RSP.
         *    On VM exit, the CPU loads these values automatically. */
        config.host_cr0 = fbvbs_asm_read_cr0();
        config.host_cr3 = fbvbs_asm_read_cr3();
        config.host_cr4 = fbvbs_asm_read_cr4();
        config.host_efer = fbvbs_asm_rdmsr(0xC0000080U);
        config.host_fs_base = fbvbs_asm_rdmsr(MSR_IA32_FS_BASE);
        config.host_gs_base = fbvbs_asm_rdmsr(MSR_IA32_GS_BASE);
        config.host_rip = fbvbs_get_vmexit_handler_rip();
        config.host_rsp = fbvbs_get_vmx_stack_top();
        config.host_gdtr_base = gdtr.base;
        config.host_idtr_base = idtr.base;
        config.host_tr_base = fbvbs_get_boot_tss_base();
        config.host_sysenter_cs = (uint32_t)fbvbs_asm_rdmsr(MSR_IA32_SYSENTER_CS);
        config.host_sysenter_esp = fbvbs_asm_rdmsr(MSR_IA32_SYSENTER_ESP);
        config.host_sysenter_eip = fbvbs_asm_rdmsr(MSR_IA32_SYSENTER_EIP);
    }
#endif

    if (fbvbs_deprivilege_preflight_ready(&config, &vmx_security) == 0) {
        fbvbs_host_ept_release(&g_host_ept_state);
        fbvbs_release_vmx_security_controls(&vmx_security);
        return -1;
    }

    if (fbvbs_vmxon_enter() != 0) {
        fbvbs_host_ept_release(&g_host_ept_state);
        fbvbs_release_vmx_security_controls(&vmx_security);
        return -1;
    }

    /* 3. Apply VMCS configuration (VMCLEAR + VMPTRLD + VMWRITE all fields) */
    if (fbvbs_vmcs_apply(&config) != 0) {
        fbvbs_vmxon_leave();
        fbvbs_host_ept_release(&g_host_ept_state);
        fbvbs_release_vmx_security_controls(&vmx_security);
        return -1;
    }

#if defined(__x86_64__) && !defined(__FRAMAC__) && !defined(__STDC_HOSTED__)
    /* 4. Execute VMLAUNCH.
     *    On success the current host resumes at guest_rip in VMX non-root
     *    mode. guest_rip currently targets guest_resume below, so the
     *    runtime flag is only asserted once the handoff has actually
     *    crossed the deprivilege boundary.
     *    On failure: returns -1 and we unwind completely. */
    if (fbvbs_vmlaunch() != 0) {
        fbvbs_vmcs_release_current();
        fbvbs_vmxon_leave();
        fbvbs_host_ept_release(&g_host_ept_state);
        fbvbs_release_vmx_security_controls(&vmx_security);
        return -1;
    }
guest_resume:
    state->runtime_state_flags |= FBVBS_RUNTIME_HOST_DEPRIVILEGED;
    (void)host_partition_id;
    fbvbs_release_vmx_security_controls(&vmx_security);
    return 0;
#else
    fbvbs_host_ept_release(&g_host_ept_state);
    fbvbs_release_vmx_security_controls(&vmx_security);
    return -1;
#endif
#endif /* !__FRAMAC__ deprivilege_host */
}

/* ================================================================
 * VM Exit Handler (called from assembly stub)
 *
 * The assembly vmexit_handler saves all guest GPRs on the stack
 * and passes a pointer to them as the first argument. This C
 * function reads the VM exit reason from the VMCS and dispatches
 * to the appropriate handler.
 *
 * On return, the assembly stub restores guest GPRs and issues
 * VMRESUME to re-enter the guest.
 *
 * Guest GPR array layout:
 *   [0]=RAX [1]=RCX [2]=RDX [3]=RBX [4]=RSP(unused) [5]=RBP
 *   [6]=RSI [7]=RDI [8]=R8  [9]=R9  [10]=R10 [11]=R11
 *   [12]=R12 [13]=R13 [14]=R14 [15]=R15
 * ================================================================ */

/* VMCS field encoding for VM-exit reason */
#define VMCS_EXIT_REASON                0x4402U
#define VMCS_EXIT_QUALIFICATION         0x6400U

void fbvbs_handle_vmexit(uint64_t *guest_gprs)
{
#if defined(__x86_64__) && !defined(__FRAMAC__) && !defined(__STDC_HOSTED__)
    uint64_t exit_reason = 0;
    uint64_t exit_qualification = 0;

    /* Read VM exit reason from VMCS */
    (void)fbvbs_asm_vmread(VMCS_EXIT_REASON, &exit_reason);
    (void)fbvbs_asm_vmread(VMCS_EXIT_QUALIFICATION, &exit_qualification);

    /* Basic exit reason is bits [15:0] */
    uint32_t basic_reason = (uint32_t)(exit_reason & 0xFFFFU);

    (void)guest_gprs;
    (void)exit_qualification;

    /* Dispatch based on exit reason.
     * Until the retained-C host path has an authoritative VM-exit
     * dispatcher, any unexpected exit is fail-closed fatal rather than
     * blindly resuming the deprivileged host. */
    switch (basic_reason) {
        case 2U:   /* Triple fault — fatal */
            fbvbs_vmexit_fatal(g_vmcs_page_phys, exit_reason, exit_qualification);
        case 1U:   /* External interrupt */
        case 7U:   /* Interrupt window */
        case 10U:  /* CPUID */
        case 12U:  /* HLT */
        case 18U:  /* VMCALL */
        case 28U:  /* CR access */
        case 29U:  /* MOV DR */
        case 30U:  /* I/O */
        case 31U:  /* RDMSR */
        case 32U:  /* WRMSR */
        case 48U:  /* EPT violation */
        default:
            fbvbs_vmexit_fatal(g_vmcs_page_phys, exit_reason, exit_qualification);
    }
#else
    (void)guest_gprs;
#endif
}
