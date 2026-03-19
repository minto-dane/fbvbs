/* SPDX-License-Identifier: BSD-2-Clause
 * FBVBS CPU Security Feature Detection and Mitigation
 *
 * Comprehensive x86_64 CPU security feature detection, per-CPU
 * vulnerability profiling, and VM exit/entry mitigation sequences.
 * All structures are multicore-aware: each logical processor
 * maintains an independent fbvbs_cpu_security_profile.
 *
 * References: plan/cpu-sec.md (81+ features), design Section 21.1-21.11
 */
#ifndef FBVBS_CPU_SECURITY_H
#define FBVBS_CPU_SECURITY_H

#include <stdint.h>

/* ================================================================
 * MSR addresses
 * ================================================================ */

#define MSR_IA32_SPEC_CTRL              0x00000048U
#define MSR_IA32_PRED_CMD               0x00000049U
#define MSR_IA32_ARCH_CAPABILITIES      0x0000010AU
#define MSR_IA32_FLUSH_CMD              0x0000010BU
#define MSR_IA32_TSX_CTRL               0x00000122U
#define MSR_IA32_MCU_OPT_CTRL          0x00000123U
#define MSR_IA32_MISC_ENABLE            0x000001A0U
#define MSR_IA32_PAT                    0x00000277U
#define MSR_IA32_SYSENTER_CS            0x00000174U
#define MSR_IA32_SYSENTER_ESP           0x00000175U
#define MSR_IA32_SYSENTER_EIP           0x00000176U
#define MSR_IA32_EFER                   0xC0000080U
#define MSR_IA32_STAR                   0xC0000081U
#define MSR_IA32_LSTAR                  0xC0000082U
#define MSR_IA32_CSTAR                  0xC0000083U
#define MSR_IA32_FMASK                  0xC0000084U

/* CET MSRs */
#define MSR_IA32_U_CET                  0x000006A0U
#define MSR_IA32_S_CET                  0x000006A2U
#define MSR_IA32_PL0_SSP                0x000006A4U
#define MSR_IA32_PL1_SSP                0x000006A5U
#define MSR_IA32_PL2_SSP                0x000006A6U
#define MSR_IA32_PL3_SSP                0x000006A7U
#define MSR_IA32_INTERRUPT_SSP_TABLE    0x000006A8U

/* AMD-specific MSRs */
#define MSR_AMD_VIRT_SPEC_CTRL          0xC001011FU
#define MSR_AMD_DE_CFG                  0xC0011029U
#define MSR_AMD_BP_CFG                  0xC001102EU

/* IA32_PKRS for Protection Keys for Supervisor */
#define MSR_IA32_PKRS                   0x000006E1U

/* ================================================================
 * IA32_ARCH_CAPABILITIES bit definitions (30+ bits)
 * ================================================================ */

#define ARCH_CAP_RDCL_NO                (1U << 0)   /* Not vulnerable to Meltdown/L1TF */
#define ARCH_CAP_IBRS_ALL               (1U << 1)   /* eIBRS: enhanced IBRS */
#define ARCH_CAP_RSBA                   (1U << 2)   /* RSB Alternate prediction */
#define ARCH_CAP_SKIP_L1DFL_VMENTRY     (1U << 3)   /* No L1D flush needed on VM entry */
#define ARCH_CAP_SSB_NO                 (1U << 4)   /* Not vulnerable to Spectre v4 */
#define ARCH_CAP_MDS_NO                 (1U << 5)   /* Not vulnerable to MDS */
#define ARCH_CAP_IF_PSCHANGE_MC_NO      (1U << 6)   /* No machine check on PS change */
#define ARCH_CAP_TSX_CTRL               (1U << 7)   /* IA32_TSX_CTRL available */
#define ARCH_CAP_TAA_NO                 (1U << 8)   /* Not vulnerable to TAA */
#define ARCH_CAP_MCU_CONTROL            (1U << 9)   /* MCU_OPT_CTRL available */
#define ARCH_CAP_MISC_PACKAGE_CTLS      (1U << 10)  /* MISC_PACKAGE_CTLS available */
#define ARCH_CAP_ENERGY_FILTERING_CTL   (1U << 11)  /* Energy filtering available */
#define ARCH_CAP_DOITM                  (1U << 12)  /* DOITM supported */
#define ARCH_CAP_SBDR_SSDP_NO           (1U << 13)  /* Not vulnerable to SBDR/SSDP */
#define ARCH_CAP_FBSDP_NO              (1U << 14)  /* Not vulnerable to FBSDP */
#define ARCH_CAP_PSDP_NO               (1U << 15)  /* Not vulnerable to PSDP */
/* bit 16 reserved */
#define ARCH_CAP_FB_CLEAR               (1U << 17)  /* VERW clears fill buffers (MMIO) */
#define ARCH_CAP_FB_CLEAR_CTRL          (1U << 18)  /* FB_CLEAR disable control */
#define ARCH_CAP_RRSBA                  (1U << 19)  /* RRSBA behavior */
#define ARCH_CAP_BHI_NO                 (1U << 20)  /* Not vulnerable to BHI */
/* bits 21-23 reserved/misc */
#define ARCH_CAP_PBRSB_NO              (1U << 24)  /* Not vulnerable to PBRSB */
/* bit 25 reserved */
#define ARCH_CAP_GDS_NO                (1U << 26)  /* Not vulnerable to Downfall/GDS */
#define ARCH_CAP_RFDS_NO               (1U << 27)  /* Not vulnerable to RFDS */
#define ARCH_CAP_RFDS_CLEAR            (1U << 28)  /* RFDS_CLEAR available */

/* ================================================================
 * IA32_SPEC_CTRL bit definitions
 * ================================================================ */

#define SPEC_CTRL_IBRS                  (1U << 0)
#define SPEC_CTRL_STIBP                 (1U << 1)
#define SPEC_CTRL_SSBD                  (1U << 2)
#define SPEC_CTRL_BHI_DIS_S            (1U << 10)
#define SPEC_CTRL_RRSBA_DIS_S          (1U << 11)
#define SPEC_CTRL_RRSBA_DIS_U          (1U << 12)

/* ================================================================
 * CR4 security-relevant bits
 * ================================================================ */

#define CR4_SMEP                        (1UL << 20)
#define CR4_SMAP                        (1UL << 21)
#define CR4_UMIP                        (1UL << 11)
#define CR4_CET                         (1UL << 23)
#define CR4_PCE                         (1UL << 8)
#define CR4_PKE                         (1UL << 22)

/* CR0 security-relevant bits */
#define CR0_WP                          (1UL << 16)

/* EFER security-relevant bits */
#define EFER_NXE                        (1UL << 11)
#define EFER_SCE                        (1UL << 0)
#define EFER_AUTOIBRS                   (1UL << 21)

/* ================================================================
 * CPU vendor identification
 * ================================================================ */

#define CPU_VENDOR_UNKNOWN              0U
#define CPU_VENDOR_INTEL                1U
#define CPU_VENDOR_AMD                  2U

/* ================================================================
 * Maximum logical processors supported
 * ================================================================ */

#define FBVBS_MAX_CPUS                  256U

/* ================================================================
 * CPUID feature detection flags
 * ================================================================ */

struct fbvbs_cpuid_features {
    /* Basic features (CPUID.7.0) */
    uint32_t has_smep;                  /* ECX=7,0: EBX[7] */
    uint32_t has_smap;                  /* ECX=7,0: EBX[20] */
    uint32_t has_cet_ss;               /* ECX=7,0: ECX[7] */
    uint32_t has_cet_ibt;              /* ECX=7,0: EDX[20] */
    uint32_t has_md_clear;             /* ECX=7,0: EDX[10] */
    uint32_t has_ibpb;                 /* ECX=7,0: EDX[26] (Intel) */
    uint32_t has_stibp;                /* ECX=7,0: EDX[27] */
    uint32_t has_umip;                 /* ECX=7,0: ECX[2] */
    uint32_t has_pku;                  /* ECX=7,0: ECX[3] */
    uint32_t has_pks;                  /* ECX=7,0: ECX[31] */
    uint32_t has_la57;                 /* ECX=7,0: ECX[16] 5-level paging */

    /* CPUID.7.1 features */
    uint32_t has_lass;                 /* ECX=7,1: EAX[6] */
    uint32_t has_fred;                 /* ECX=7,1: EAX[17] */

    /* CPUID.7.2 features */
    uint32_t has_bhi_ctrl;             /* ECX=7,2: EDX[4] */

    /* Virtualization features */
    uint32_t has_vmx;                  /* ECX=1: ECX[5] (Intel) */
    uint32_t has_svm;                  /* CPUID 0x80000001: ECX[2] (AMD) */
    uint32_t has_ept;                  /* VMX: secondary proc bit 1 */
    uint32_t has_vpid;                 /* VMX: secondary proc bit 5 */
    uint32_t has_mbec;                 /* VMX: secondary proc bit 22 */
    uint32_t has_ept_violation_ve;     /* VMX: secondary proc bit 18 */
    uint32_t has_pml;                  /* VMX: secondary proc bit 17 */
    uint32_t has_unrestricted_guest;   /* VMX: secondary proc bit 7 */
    uint32_t has_vmfunc;               /* VMX: secondary proc bit 13 */
    uint32_t has_preemption_timer;     /* VMX: pin-based bit 6 */
    uint32_t has_posted_interrupts;    /* VMX: pin-based bit 7 */
    uint32_t has_notify_vm_exit;       /* VMX: secondary proc */
    uint32_t has_bus_lock_detect;      /* VMX: secondary proc */
    uint32_t has_hlat;                 /* VMX: tertiary proc */

    /* AMD-specific */
    uint32_t has_npt;                  /* AMD NPT */
    uint32_t has_gmet;                 /* Fn8000_000A:EDX[24] */
    uint32_t has_avic;                 /* Fn8000_000A:EDX[13] */
    uint32_t has_x2avic;              /* AMD Zen 3/4+ */
    uint32_t has_vgif;                 /* Fn8000_000A:EDX[16] */
    uint32_t has_vmcb_clean;           /* Fn8000_000A:EDX[5] */
    uint32_t has_decode_assists;       /* Fn8000_000A:EDX[7] */
    uint32_t has_vnmi;                 /* Fn8000_000A:EDX[25] Zen 4 */
    uint32_t has_pause_filter;         /* Fn8000_000A:EDX[10] */
    uint32_t has_lbr_virt;             /* Fn8000_000A:EDX[1] */
    uint32_t has_sss_check;            /* Fn8000_000A:EDX[19] */
    uint32_t has_bus_lock_trap;        /* AMD Zen 5 */

    /* AMD speculative features */
    uint32_t has_amd_ibpb;            /* Fn8000_0008:EBX[12] */
    uint32_t has_amd_stibp;           /* Fn8000_0008:EBX[15] */
    uint32_t has_amd_ibpb_ret;        /* Fn8000_0008:EBX[30] IBPB clears RSB */
    uint32_t has_autoibrs;            /* Fn8000_0021:EAX[8] */
    uint32_t has_amd_ssbd;            /* Fn8000_0008:EBX[24] */

    /* AMD SEV features */
    uint32_t has_sev;                  /* Fn8000_001F:EAX[1] */
    uint32_t has_sev_es;              /* Fn8000_001F:EAX[3] */
    uint32_t has_sev_snp;             /* Fn8000_001F:EAX[4] */

    /* Memory encryption */
    uint32_t has_tme;                  /* Intel TME */
    uint32_t has_mktme;               /* Intel MKTME */
    uint32_t has_sme;                  /* AMD SME */

    /* Boot/attestation */
    uint32_t has_txt;                  /* Intel TXT (GETSEC) */
    uint32_t has_skinit;               /* AMD SKINIT */

    /* Misc */
    uint32_t has_pcid;                 /* CPUID.1:ECX[17] */
    uint32_t has_aesni;               /* CPUID.1:ECX[25] */
    uint32_t has_nx;                   /* CPUID 0x80000001: EDX[20] */
};

/* ================================================================
 * Per-CPU vulnerability profile
 * ================================================================ */

struct fbvbs_vuln_profile {
    /* Vulnerability immunity flags (from IA32_ARCH_CAPABILITIES) */
    uint32_t arch_capabilities_valid;  /* 1 if MSR was read */
    uint32_t arch_capabilities_lo;     /* Low 32 bits */
    uint32_t arch_capabilities_hi;     /* High 32 bits (future) */
    uint32_t reserved0;

    /* Per-vulnerability: 0 = vulnerable, 1 = immune */
    uint32_t immune_meltdown;          /* RDCL_NO */
    uint32_t immune_l1tf;              /* RDCL_NO or SKIP_L1DFL */
    uint32_t immune_mds;               /* MDS_NO */
    uint32_t immune_taa;               /* TAA_NO */
    uint32_t immune_ssb;               /* SSB_NO */
    uint32_t immune_pbrsb;             /* PBRSB_NO */
    uint32_t immune_gds;               /* GDS_NO */
    uint32_t immune_rfds;              /* RFDS_NO */
    uint32_t immune_bhi;               /* BHI_NO or BHI_DIS_S available */
    uint32_t immune_mmio_stale;        /* FB_CLEAR available */
    uint32_t immune_srso;              /* AMD Zen 5+ or mitigated */
    uint32_t immune_retbleed;          /* Mitigated by eIBRS/AutoIBRS */

    /* Required mitigation actions (computed from above) */
    uint32_t need_l1d_flush;           /* L1D flush on VM entry */
    uint32_t need_verw;                /* VERW on privilege transition */
    uint32_t need_rsb_fill;            /* RSB fill on VM exit */
    uint32_t need_pbrsb_sequence;      /* PBRSB mitigation after VM exit */
    uint32_t need_bhb_clear;           /* Software BHB clearing */
    uint32_t need_tsx_disable;         /* TSX should be disabled */
    uint32_t need_srso_mitigation;     /* SRSO safe-ret thunk */
    uint32_t need_retbleed_mitigation; /* Retbleed mitigation */
    uint32_t need_lfence_serialize;    /* AMD LFENCE serialization */
};

/* ================================================================
 * Per-CPU speculative execution mitigation state
 * ================================================================ */

struct fbvbs_spec_ctrl_state {
    uint64_t host_spec_ctrl;           /* Host IA32_SPEC_CTRL value */
    uint64_t guest_spec_ctrl;          /* Guest IA32_SPEC_CTRL (per-vCPU) */
};

/* ================================================================
 * Per-CPU CET state (saved/restored on partition transition)
 * ================================================================ */

struct fbvbs_cet_state {
    uint64_t s_cet;                    /* IA32_S_CET */
    uint64_t u_cet;                    /* IA32_U_CET */
    uint64_t pl0_ssp;                  /* IA32_PL0_SSP */
    uint64_t pl1_ssp;                  /* IA32_PL1_SSP */
    uint64_t pl2_ssp;                  /* IA32_PL2_SSP */
    uint64_t pl3_ssp;                  /* IA32_PL3_SSP */
    uint64_t isst_addr;               /* IA32_INTERRUPT_SSP_TABLE_ADDR */
    uint64_t reserved0;
};

/* ================================================================
 * Per-CPU debug register state
 * ================================================================ */

struct fbvbs_debug_state {
    uint64_t dr0;
    uint64_t dr1;
    uint64_t dr2;
    uint64_t dr3;
    uint64_t dr6;                      /* Debug status */
    uint64_t dr7;                      /* Debug control */
};

/* ================================================================
 * CR pinning configuration
 * ================================================================ */

struct fbvbs_cr_pin_config {
    uint64_t cr0_pin_mask;             /* Bits that must remain set in CR0 */
    uint64_t cr0_pin_value;            /* Required values for pinned CR0 bits */
    uint64_t cr4_pin_mask;             /* Bits that must remain set in CR4 */
    uint64_t cr4_pin_value;            /* Required values for pinned CR4 bits */
    uint64_t efer_pin_mask;            /* Bits that must remain set in EFER */
    uint64_t efer_pin_value;           /* Required values for pinned EFER bits */
};

/* ================================================================
 * IOMMU detection state
 * ================================================================ */

#define IOMMU_TYPE_NONE                 0U
#define IOMMU_TYPE_VTD                  1U
#define IOMMU_TYPE_AMD_VI               2U

struct fbvbs_iommu_state {
    uint32_t iommu_type;               /* IOMMU_TYPE_* */
    uint32_t interrupt_remapping;       /* 1 if interrupt remapping available */
    uint32_t dma_remapping;            /* 1 if DMA remapping available */
    uint32_t kernel_dma_protection;    /* 1 if kernel DMA protection active */
    uint32_t acs_available;            /* 1 if ACS checking is possible */
    uint32_t scalable_mode;            /* Intel VT-d scalable mode */
    uint32_t pasid_support;            /* PASID capability */
    uint32_t reserved0;
};

/* ================================================================
 * Boot integrity detection state
 * ================================================================ */

struct fbvbs_boot_integrity {
    uint32_t drtm_available;           /* TXT or SKINIT detected */
    uint32_t drtm_type;               /* 0=none, 1=TXT, 2=SKINIT */
    uint32_t boot_guard_active;        /* Intel Boot Guard / AMD PSB */
    uint32_t tpm_present;              /* TPM 2.0 detected */
    uint32_t tpm_version;              /* TPM version (20 = 2.0) */
    uint32_t secure_boot_active;       /* UEFI Secure Boot */
    uint32_t measured_boot_active;     /* Measured boot chain */
    uint32_t reserved0;
};

/* ================================================================
 * Complete per-CPU security profile
 * One instance per logical processor, indexed by cpu_id.
 * ================================================================ */

struct fbvbs_cpu_security_profile {
    uint32_t cpu_id;                   /* Logical processor index */
    uint32_t vendor;                   /* CPU_VENDOR_* */
    uint32_t family;                   /* CPU family */
    uint32_t model;                    /* CPU model */
    uint32_t stepping;                 /* CPU stepping */
    uint32_t microcode_version;        /* Microcode revision */
    uint32_t smt_enabled;             /* SMT/HT active on this core */
    uint32_t initialized;              /* 1 if profile has been built */

    struct fbvbs_cpuid_features features;
    struct fbvbs_vuln_profile   vuln;
    struct fbvbs_cr_pin_config  cr_pins;
};

/* ================================================================
 * Global security state (shared, immutable after init)
 * ================================================================ */

struct fbvbs_global_security_state {
    uint32_t cpu_count;                /* Number of logical processors */
    uint32_t vendor;                   /* CPU_VENDOR_* (all CPUs same) */
    uint32_t profiles_consistent;      /* 1 if all CPUs have same features */
    uint32_t reserved0;

    struct fbvbs_iommu_state     iommu;
    struct fbvbs_boot_integrity  boot;

    /* Host SPEC_CTRL value (computed once, applied on all CPUs) */
    uint64_t host_spec_ctrl_value;

    /* Aggregated mitigation requirements (worst-case across all CPUs) */
    struct fbvbs_vuln_profile    worst_case_vuln;
};

/* ================================================================
 * Function declarations (all with ACSL contracts)
 * ================================================================ */

/*@ requires \valid(profile);
    requires cpu_id < FBVBS_MAX_CPUS;
    assigns *profile;
    ensures \result == 0;
    ensures profile->initialized == 1;
    ensures profile->vendor == CPU_VENDOR_INTEL
         || profile->vendor == CPU_VENDOR_AMD
         || profile->vendor == CPU_VENDOR_UNKNOWN;
*/
int fbvbs_cpu_detect_features(uint32_t cpu_id,
                              struct fbvbs_cpu_security_profile *profile);

/*@ requires \valid(profile);
    requires profile->initialized == 1;
    assigns profile->vuln;
*/
int fbvbs_cpu_build_vuln_profile(struct fbvbs_cpu_security_profile *profile);

/*@ requires \valid(profile);
    requires profile->initialized == 1;
    assigns profile->cr_pins;
*/
int fbvbs_cpu_compute_cr_pins(struct fbvbs_cpu_security_profile *profile);

/*@ requires \valid(state);
    requires cpu_count <= FBVBS_MAX_CPUS;
    requires cpu_count >= 1;
    requires \valid_read(profiles + (0 .. cpu_count - 1));
    requires \separated(profiles + (0 .. cpu_count - 1), state);
    assigns state->host_spec_ctrl_value,
            state->worst_case_vuln,
            state->profiles_consistent;
    ensures \result == 0 || \result == -1;
*/
int fbvbs_cpu_compute_global_mitigations(
    const struct fbvbs_cpu_security_profile *profiles,
    uint32_t cpu_count,
    struct fbvbs_global_security_state *state);

/*@ requires \valid(state);
    assigns state->iommu;
*/
int fbvbs_iommu_detect(struct fbvbs_global_security_state *state);

/*@ requires \valid(state);
    assigns state->boot;
*/
int fbvbs_boot_integrity_detect(struct fbvbs_global_security_state *state);

/*@ requires \valid_read(profile_a);
    requires \valid_read(profile_b);
    requires profile_a->initialized == 1;
    requires profile_b->initialized == 1;
    assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
int fbvbs_cpu_verify_consistency(
    const struct fbvbs_cpu_security_profile *profile_a,
    const struct fbvbs_cpu_security_profile *profile_b);

/* ================================================================
 * VM exit/entry mitigation sequence helpers
 *
 * These are called per-core during partition transitions.
 * Each function is idempotent and lock-free.
 * ================================================================ */

/*@ requires \valid_read(vuln);
    requires \valid(spec_state);
    assigns spec_state->guest_spec_ctrl;
*/
void fbvbs_vmexit_mitigate(const struct fbvbs_vuln_profile *vuln,
                           struct fbvbs_spec_ctrl_state *spec_state,
                           uint32_t is_cross_partition);

/*@ requires \valid_read(vuln);
    requires \valid(spec_state);
    assigns spec_state->host_spec_ctrl;
*/
void fbvbs_vmentry_mitigate(const struct fbvbs_vuln_profile *vuln,
                            struct fbvbs_spec_ctrl_state *spec_state);

/*@ requires \valid(guest_cet);
    requires \valid_read(host_cet);
    assigns *guest_cet;
*/
void fbvbs_cet_save_guest(struct fbvbs_cet_state *guest_cet,
                          const struct fbvbs_cet_state *host_cet);

/*@ requires \valid_read(guest_cet);
    assigns \nothing;
*/
void fbvbs_cet_restore_guest(const struct fbvbs_cet_state *guest_cet);

/*@ requires \valid(guest_dbg);
    assigns *guest_dbg;
*/
void fbvbs_debug_save_guest(struct fbvbs_debug_state *guest_dbg);

/*@ requires \valid_read(guest_dbg);
    assigns \nothing;
*/
void fbvbs_debug_restore_guest(const struct fbvbs_debug_state *guest_dbg);

#endif /* FBVBS_CPU_SECURITY_H */
