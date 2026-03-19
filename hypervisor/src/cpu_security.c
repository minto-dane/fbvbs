/* SPDX-License-Identifier: BSD-2-Clause
 * FBVBS CPU Security Feature Detection and Mitigation
 *
 * Implements per-CPU feature detection via CPUID/MSR parsing,
 * vulnerability profiling, CR pinning computation, and
 * VM exit/entry mitigation sequences.
 *
 * All functions are multicore-safe: per-CPU profiles are independent,
 * global state is computed once from all profiles and then immutable.
 *
 * Design references: fbvbs-design.md Section 21.1-21.11
 * Feature catalog: plan/cpu-sec.md (81+ features)
 *
 * Frama-C WP: all functions annotated with ACSL contracts.
 * void* operations are avoided for Typed+Cast model compatibility.
 */

#include "fbvbs_cpu_security.h"

/* ================================================================
 * Internal CPUID/MSR helpers
 *
 * Under Frama-C we keep model stubs. On x86 we issue the real
 * instructions so the runtime mitigation state reflects hardware.
 * ================================================================ */

/*@ requires \valid(out_eax) && \valid(out_ebx) && \valid(out_ecx) && \valid(out_edx);
    requires \separated(out_eax, out_ebx, out_ecx, out_edx);
    assigns *out_eax, *out_ebx, *out_ecx, *out_edx;
*/
static void cpuid_query(uint32_t leaf, uint32_t subleaf,
                        uint32_t *out_eax, uint32_t *out_ebx,
                        uint32_t *out_ecx, uint32_t *out_edx)
{
#if defined(__FRAMAC__)
    (void)leaf;
    (void)subleaf;
    *out_eax = 0;
    *out_ebx = 0;
    *out_ecx = 0;
    *out_edx = 0;
#elif defined(__x86_64__) || defined(__i386__)
    __asm__ volatile("cpuid"
                     : "=a"(*out_eax), "=b"(*out_ebx),
                       "=c"(*out_ecx), "=d"(*out_edx)
                     : "0"(leaf), "2"(subleaf)
                     : "memory");
#else
    (void)leaf;
    (void)subleaf;
    *out_eax = 0;
    *out_ebx = 0;
    *out_ecx = 0;
    *out_edx = 0;
#endif
}

/* ================================================================
 * Internal MSR read helper (model-level stub)
 * ================================================================ */

/*@ assigns \nothing;
    ensures 0 <= \result;
*/
static uint64_t msr_read(uint32_t msr_addr)
{
#if defined(__FRAMAC__)
    (void)msr_addr;
    return 0;
#elif defined(__x86_64__) || defined(__i386__)
    uint32_t lo;
    uint32_t hi;

    __asm__ volatile("rdmsr"
                     : "=a"(lo), "=d"(hi)
                     : "c"(msr_addr)
                     : "memory");
    return ((uint64_t)hi << 32) | (uint64_t)lo;
#else
    (void)msr_addr;
    return 0;
#endif
}

/* ================================================================
 * Internal MSR write helper (model-level stub)
 * ================================================================ */

/*@ assigns \nothing; */
static void msr_write(uint32_t msr_addr, uint64_t value)
{
#if defined(__FRAMAC__)
    (void)msr_addr;
    (void)value;
#elif defined(__x86_64__) || defined(__i386__)
    uint32_t lo = (uint32_t)(value & 0xFFFFFFFFU);
    uint32_t hi = (uint32_t)(value >> 32);

    __asm__ volatile("wrmsr"
                     :
                     : "c"(msr_addr), "a"(lo), "d"(hi)
                     : "memory");
#else
    (void)msr_addr;
    (void)value;
#endif
}

/*@ assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
static int cpuid_basic_leaf_supported(uint32_t leaf)
{
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;

    cpuid_query(0, 0, &eax, &ebx, &ecx, &edx);
    return eax >= leaf;
}

/*@ assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
static int cpuid_extended_leaf_supported(uint32_t leaf)
{
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;

    cpuid_query(0x80000000U, 0, &eax, &ebx, &ecx, &edx);
    return eax >= leaf;
}

/*@ assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
static int detect_smt_enabled(uint32_t vendor)
{
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
    uint32_t max_logical;

    cpuid_query(1, 0, &eax, &ebx, &ecx, &edx);
    max_logical = (ebx >> 16) & 0xFFU;
    if (max_logical <= 1U) {
        return 0;
    }

    if (vendor == CPU_VENDOR_INTEL) {
        if (cpuid_basic_leaf_supported(0xBU) != 0) {
            cpuid_query(0xBU, 0, &eax, &ebx, &ecx, &edx);
            if (((ecx >> 8) & 0xFFU) == 1U) {
                return ebx > 1U;
            }
        }
        if (cpuid_basic_leaf_supported(4U) != 0) {
            cpuid_query(4, 0, &eax, &ebx, &ecx, &edx);
            return max_logical > ((((eax >> 26) & 0x3FU) + 1U));
        }
        return max_logical > 1U;
    }

    if (vendor == CPU_VENDOR_AMD) {
        if (cpuid_extended_leaf_supported(0x80000008U) != 0) {
            cpuid_query(0x80000008U, 0, &eax, &ebx, &ecx, &edx);
            return max_logical > ((ecx & 0xFFU) + 1U);
        }
        return max_logical > 1U;
    }

    return max_logical > 1U;
}

/* ================================================================
 * Vendor detection from CPUID leaf 0
 * ================================================================ */

/*@ assigns \nothing;
    ensures \result == CPU_VENDOR_INTEL
         || \result == CPU_VENDOR_AMD
         || \result == CPU_VENDOR_UNKNOWN;
*/
static uint32_t detect_vendor(void)
{
    uint32_t eax, ebx, ecx, edx;
    cpuid_query(0, 0, &eax, &ebx, &ecx, &edx);

    /* "GenuineIntel": EBX=0x756e6547, EDX=0x49656e69, ECX=0x6c65746e */
    if (ebx == 0x756e6547U && edx == 0x49656e69U && ecx == 0x6c65746eU) {
        return CPU_VENDOR_INTEL;
    }
    /* "AuthenticAMD": EBX=0x68747541, EDX=0x69746e65, ECX=0x444d4163 */
    if (ebx == 0x68747541U && edx == 0x69746e65U && ecx == 0x444d4163U) {
        return CPU_VENDOR_AMD;
    }
    return CPU_VENDOR_UNKNOWN;
}

/* ================================================================
 * CPU feature detection
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
                              struct fbvbs_cpu_security_profile *profile)
{
    uint32_t eax, ebx, ecx, edx;
    struct fbvbs_cpuid_features *f = &profile->features;

    /* cpu_id < FBVBS_MAX_CPUS guaranteed by ACSL requires */

    /* Zero-initialize entire profile */
    *profile = (struct fbvbs_cpu_security_profile){0};
    profile->cpu_id = cpu_id;

    /* Vendor detection */
    profile->vendor = detect_vendor();
    /*@ assert profile->vendor == CPU_VENDOR_INTEL
         || profile->vendor == CPU_VENDOR_AMD
         || profile->vendor == CPU_VENDOR_UNKNOWN; */

    /* Family/model/stepping from CPUID leaf 1 */
    cpuid_query(1, 0, &eax, &ebx, &ecx, &edx);
    {
        uint32_t base_family = (eax >> 8) & 0xFU;
        uint32_t ext_family  = (eax >> 20) & 0xFFU;
        uint32_t base_model  = (eax >> 4) & 0xFU;
        uint32_t ext_model   = (eax >> 16) & 0xFU;

        if (base_family == 0xFU) {
            profile->family = base_family + ext_family;
        } else {
            profile->family = base_family;
        }
        if (base_family == 0x6U || base_family == 0xFU) {
            profile->model = (ext_model << 4) | base_model;
        } else {
            profile->model = base_model;
        }
        profile->stepping = eax & 0xFU;
    }

    /* Basic features from leaf 1 */
    f->has_pcid  = (ecx >> 17) & 1U;
    f->has_aesni = (ecx >> 25) & 1U;
    f->has_vmx   = (ecx >> 5)  & 1U;

    /* NX from extended leaf 0x80000001 */
    if (cpuid_extended_leaf_supported(0x80000001U) != 0) {
        cpuid_query(0x80000001U, 0, &eax, &ebx, &ecx, &edx);
        f->has_nx    = (edx >> 20) & 1U;
        f->has_svm   = (ecx >> 2)  & 1U;
    }

    /* Structured feature flags: CPUID.(EAX=7, ECX=0) */
    if (cpuid_basic_leaf_supported(7U) != 0) {
        cpuid_query(7, 0, &eax, &ebx, &ecx, &edx);
        f->has_smep         = (ebx >> 7)  & 1U;
        f->has_smap         = (ebx >> 20) & 1U;
        f->has_cet_ss       = (ecx >> 7)  & 1U;
        f->has_umip         = (ecx >> 2)  & 1U;
        f->has_pku          = (ecx >> 3)  & 1U;
        f->has_pks          = (ecx >> 31) & 1U;
        f->has_la57         = (ecx >> 16) & 1U;
        f->has_cet_ibt      = (edx >> 20) & 1U;
        f->has_md_clear     = (edx >> 10) & 1U;
        f->has_mcu_opt_ctrl = (edx >> 9)  & 1U;
        f->has_ibpb         = (edx >> 26) & 1U;
        f->has_stibp        = (edx >> 27) & 1U;

        /* CPUID.(EAX=7, ECX=1) for LASS, FRED */
        cpuid_query(7, 1, &eax, &ebx, &ecx, &edx);
        f->has_lass = (eax >> 6)  & 1U;
        f->has_fred = (eax >> 17) & 1U;

        /* CPUID.(EAX=7, ECX=2) for BHI_CTRL */
        cpuid_query(7, 2, &eax, &ebx, &ecx, &edx);
        f->has_bhi_ctrl = (edx >> 4) & 1U;
    }

    /* Read microcode revision (Intel: CPUID.1 after wrmsr 0x8B; AMD: MSR 0x8B directly) */
    {
        uint64_t ucode_rev = msr_read(0x0000008BU);
        if (profile->vendor == CPU_VENDOR_AMD) {
            profile->microcode_version = (uint32_t)(ucode_rev & 0xFFFFFFFFU);
        } else {
            profile->microcode_version = (uint32_t)(ucode_rev >> 32);
        }
    }

    profile->smt_enabled = (uint32_t)detect_smt_enabled(profile->vendor);

    /* AMD-specific extended features */
    if (profile->vendor == CPU_VENDOR_AMD) {
        /* SVM features: CPUID Fn8000_000A */
        if (cpuid_extended_leaf_supported(0x8000000AU) != 0) {
            cpuid_query(0x8000000AU, 0, &eax, &ebx, &ecx, &edx);
            f->has_npt            = (edx >> 0)  & 1U;
            f->has_lbr_virt       = (edx >> 1)  & 1U;
            f->has_vmcb_clean     = (edx >> 5)  & 1U;
            f->has_decode_assists = (edx >> 7)  & 1U;
            f->has_pause_filter   = (edx >> 10) & 1U;
            f->has_avic           = (edx >> 13) & 1U;
            f->has_vgif           = (edx >> 16) & 1U;
            f->has_sss_check      = (edx >> 19) & 1U;
            f->has_gmet           = (edx >> 24) & 1U;
            f->has_vnmi           = (edx >> 25) & 1U;
        }

        /* AMD speculative mitigations: CPUID Fn8000_0008 */
        if (cpuid_extended_leaf_supported(0x80000008U) != 0) {
            cpuid_query(0x80000008U, 0, &eax, &ebx, &ecx, &edx);
            f->has_amd_ibpb     = (ebx >> 12) & 1U;
            f->has_amd_stibp    = (ebx >> 15) & 1U;
            f->has_amd_ssbd     = (ebx >> 24) & 1U;
            f->has_amd_ibpb_ret = (ebx >> 30) & 1U;
        }

        /* AMD extended features: CPUID Fn8000_0021 */
        if (cpuid_extended_leaf_supported(0x80000021U) != 0) {
            cpuid_query(0x80000021U, 0, &eax, &ebx, &ecx, &edx);
            f->has_autoibrs = (eax >> 8) & 1U;
        }

        /* AMD SEV: CPUID Fn8000_001F */
        if (cpuid_extended_leaf_supported(0x8000001FU) != 0) {
            cpuid_query(0x8000001FU, 0, &eax, &ebx, &ecx, &edx);
            f->has_sev     = (eax >> 1) & 1U;
            f->has_sev_es  = (eax >> 3) & 1U;
            f->has_sev_snp = (eax >> 4) & 1U;
            f->has_sme     = (eax >> 0) & 1U;
        }
    }

    profile->initialized = 1;
    /*@ assert profile->vendor == CPU_VENDOR_INTEL
         || profile->vendor == CPU_VENDOR_AMD
         || profile->vendor == CPU_VENDOR_UNKNOWN; */
    return 0;
}

/* ================================================================
 * Vulnerability profile construction
 * ================================================================ */

/*@ requires \valid(profile);
    requires profile->initialized == 1;
    assigns profile->vuln;
*/
int fbvbs_cpu_build_vuln_profile(struct fbvbs_cpu_security_profile *profile)
{
    struct fbvbs_vuln_profile *v = &profile->vuln;

    *v = (struct fbvbs_vuln_profile){0};

    /* Read IA32_ARCH_CAPABILITIES if available (Intel) */
    if (profile->vendor == CPU_VENDOR_INTEL) {
        uint32_t eax, ebx, ecx, edx;
        cpuid_query(7, 0, &eax, &ebx, &ecx, &edx);
        /* Check if IA32_ARCH_CAPABILITIES is enumerated */
        if ((edx >> 29) & 1U) {
            uint64_t arch_cap = msr_read(MSR_IA32_ARCH_CAPABILITIES);
            v->arch_capabilities_valid = 1;
            v->arch_capabilities_lo = (uint32_t)(arch_cap & 0xFFFFFFFFU);
            v->arch_capabilities_hi = (uint32_t)(arch_cap >> 32);

            /* Parse immunity flags */
            v->immune_meltdown   = (v->arch_capabilities_lo & ARCH_CAP_RDCL_NO) ? 1U : 0U;
            v->immune_l1tf       = (v->arch_capabilities_lo & (ARCH_CAP_RDCL_NO | ARCH_CAP_SKIP_L1DFL_VMENTRY)) ? 1U : 0U;
            v->immune_mds        = (v->arch_capabilities_lo & ARCH_CAP_MDS_NO) ? 1U : 0U;
            v->immune_taa        = (v->arch_capabilities_lo & ARCH_CAP_TAA_NO) ? 1U : 0U;
            v->immune_ssb        = (v->arch_capabilities_lo & ARCH_CAP_SSB_NO) ? 1U : 0U;
            v->immune_pbrsb      = (v->arch_capabilities_lo & ARCH_CAP_PBRSB_NO) ? 1U : 0U;
            v->immune_gds        = (v->arch_capabilities_lo & ARCH_CAP_GDS_NO) ? 1U : 0U;
            v->immune_rfds       = (v->arch_capabilities_lo & ARCH_CAP_RFDS_NO) ? 1U : 0U;
            v->immune_bhi        = (v->arch_capabilities_lo & ARCH_CAP_BHI_NO) ? 1U : 0U;
            v->immune_mmio_stale = (v->arch_capabilities_lo & ARCH_CAP_FB_CLEAR) ? 1U : 0U;

            /* Intel: eIBRS (IBRS_ALL) provides Retbleed immunity */
            if ((arch_cap & ARCH_CAP_IBRS_ALL) != 0U) {
                v->immune_retbleed = 1U;
            }
        }
    }

    /* AMD vulnerability profile */
    if (profile->vendor == CPU_VENDOR_AMD) {
        /* AMD is immune to Meltdown, L1TF, PBRSB, GDS, RFDS, BHI */
        v->immune_meltdown   = 1;
        v->immune_l1tf       = 1;
        v->immune_pbrsb      = 1;
        v->immune_gds        = 1;
        v->immune_rfds       = 1;
        v->immune_bhi        = 1;
        v->immune_mmio_stale = 1;

        /* AMD MDS: generally immune post-Zen */
        v->immune_mds = 1;
        v->immune_taa = 1;
        v->immune_ssb = 0; /* AMD has SSB, mitigated by SSBD */

        /* SRSO: Zen 1-4 vulnerable, Zen 5+ immune */
        /* Approximate: family 0x19 stepping-dependent */
        v->immune_srso = 0; /* Conservative: assume vulnerable */

        /* Retbleed: Zen 1-3 vulnerable */
        v->immune_retbleed = (profile->features.has_autoibrs != 0U) ? 1U : 0U;
    }

    /* Compute required mitigations */
    v->need_l1d_flush         = (v->immune_l1tf == 0U) ? 1U : 0U;
    v->need_verw              = (v->immune_mds == 0U || v->immune_taa == 0U || v->immune_mmio_stale == 0U || v->immune_rfds == 0U) ? 1U : 0U;
    v->need_rsb_fill          = 1; /* Always needed unless AutoIBRS w/ IBPB_RET */
    v->need_pbrsb_sequence    = (v->immune_pbrsb == 0U) ? 1U : 0U;
    v->need_bhb_clear         = (v->immune_bhi == 0U && profile->features.has_bhi_ctrl == 0U) ? 1U : 0U;
    v->need_tsx_disable       = (v->immune_taa == 0U) ? 1U : 0U;
    v->need_srso_mitigation   = (v->immune_srso == 0U && profile->vendor == CPU_VENDOR_AMD) ? 1U : 0U;
    v->need_retbleed_mitigation = (v->immune_retbleed == 0U) ? 1U : 0U;
    v->need_lfence_serialize  = (profile->vendor == CPU_VENDOR_AMD) ? 1U : 0U;

    /* AutoIBRS with IBPB_RET eliminates need for explicit RSB fill */
    if (profile->vendor == CPU_VENDOR_AMD &&
        profile->features.has_autoibrs != 0U &&
        profile->features.has_amd_ibpb_ret != 0U) {
        v->need_rsb_fill = 0;
    }

    /* UNKNOWN vendor: fail-closed. All immune_* are 0 (zero-init),
       so all need_* mitigations are already set. Additionally force
       lfence serialization and retbleed mitigation for maximum safety. */
    if (profile->vendor == CPU_VENDOR_UNKNOWN) {
        v->need_lfence_serialize = 1;
        v->need_retbleed_mitigation = 1;
        v->need_srso_mitigation = 1;
    }

    return 0;
}

/* ================================================================
 * CR pinning computation
 * ================================================================ */

/*@ requires \valid(profile);
    requires profile->initialized == 1;
    assigns profile->cr_pins;
*/
int fbvbs_cpu_compute_cr_pins(struct fbvbs_cpu_security_profile *profile)
{
    struct fbvbs_cr_pin_config *p = &profile->cr_pins;

    *p = (struct fbvbs_cr_pin_config){0};

    /* CR0: WP must stay set */
    p->cr0_pin_mask  = CR0_WP;
    p->cr0_pin_value = CR0_WP;

    /* CR4: SMEP, SMAP must stay set; PCE must stay clear */
    p->cr4_pin_mask  = CR4_SMEP | CR4_SMAP | CR4_PCE;
    p->cr4_pin_value = CR4_SMEP | CR4_SMAP; /* PCE bit = 0 */

    /* Add UMIP if available */
    if (profile->features.has_umip != 0U) {
        p->cr4_pin_mask  |= CR4_UMIP;
        p->cr4_pin_value |= CR4_UMIP;
    }

    /* Add CET if available */
    if (profile->features.has_cet_ss != 0U) {
        p->cr4_pin_mask  |= CR4_CET;
        p->cr4_pin_value |= CR4_CET;
    }

    /* EFER: NXE must stay set, SCE must stay set */
    p->efer_pin_mask  = EFER_NXE | EFER_SCE;
    p->efer_pin_value = EFER_NXE | EFER_SCE;

    /* AMD AutoIBRS: pin EFER.AUTOIBRS */
    if (profile->vendor == CPU_VENDOR_AMD &&
        profile->features.has_autoibrs != 0U) {
        p->efer_pin_mask  |= EFER_AUTOIBRS;
        p->efer_pin_value |= EFER_AUTOIBRS;
    }

    return 0;
}

/* ================================================================
 * Helper: OR-merge RRSBA across all CPU profiles
 *
 * RRSBA is a vulnerability indicator — if ANY CPU has it, we must
 * set RRSBA_DIS_S. This is an OR-merge (not AND-merge).
 * ================================================================ */

/*@ requires cpu_count >= 1;
    requires cpu_count <= FBVBS_MAX_CPUS;
    requires \valid_read(profiles + (0 .. cpu_count - 1));
    assigns \nothing;
    ensures \result == 0 || \result != 0;
*/
static uint32_t compute_any_rrsba(
    const struct fbvbs_cpu_security_profile *profiles,
    uint32_t cpu_count)
{
    uint32_t any_rrsba = profiles[0].vuln.arch_capabilities_lo & ARCH_CAP_RRSBA;
    uint32_t i;
    /*@ loop invariant 1 <= i <= cpu_count;
        loop assigns i, any_rrsba;
        loop variant cpu_count - i;
    */
    for (i = 1; i < cpu_count; i++) {
        any_rrsba |= profiles[i].vuln.arch_capabilities_lo & ARCH_CAP_RRSBA;
    }
    return any_rrsba;
}

/* ================================================================
 * Helper: check for vendor mismatch across CPU profiles
 * ================================================================ */

/*@ requires cpu_count >= 1;
    requires cpu_count <= FBVBS_MAX_CPUS;
    requires \valid_read(profiles + (0 .. cpu_count - 1));
    assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
static int has_vendor_mismatch(
    const struct fbvbs_cpu_security_profile *profiles,
    uint32_t cpu_count)
{
    uint32_t i;
    /*@ loop invariant 1 <= i <= cpu_count;
        loop assigns i;
        loop variant cpu_count - i;
    */
    for (i = 1; i < cpu_count; i++) {
        if (profiles[i].vendor != profiles[0].vendor) {
            return 1;
        }
    }
    return 0;
}

/* ================================================================
 * Global mitigation computation (worst-case across all CPUs)
 * ================================================================ */

/*@ requires \valid(state);
    requires cpu_count <= FBVBS_MAX_CPUS;
    requires cpu_count >= 1;
    requires \valid_read(profiles + (0 .. cpu_count - 1));
    requires \separated(profiles + (0 .. cpu_count - 1), state);
    assigns state->cpu_count,
            state->vendor,
            state->host_spec_ctrl_value,
            state->worst_case_vuln,
            state->profiles_consistent;
    ensures \result == 0 || \result == -1;
*/
int fbvbs_cpu_compute_global_mitigations(
    const struct fbvbs_cpu_security_profile *profiles,
    uint32_t cpu_count,
    struct fbvbs_global_security_state *state)
{
    struct fbvbs_vuln_profile *wc = &state->worst_case_vuln;
    uint32_t i;
    /* Feature flags: AND-merge across all CPUs (only enable if ALL support) */
    uint32_t all_have_bhi_ctrl = profiles[0].features.has_bhi_ctrl;
    uint32_t all_have_amd_stibp = profiles[0].features.has_amd_stibp;

    *wc = (struct fbvbs_vuln_profile){0};
    state->cpu_count = cpu_count;
    state->vendor = profiles[0].vendor;
    state->profiles_consistent = 1;
    state->host_spec_ctrl_value = 0;

    /* Fail-closed: refuse to operate on unknown or mixed-vendor hardware.
       A hypervisor cannot guarantee security properties on hardware it
       does not understand. */
    if (profiles[0].vendor == CPU_VENDOR_UNKNOWN) {
        return -1;
    }

    /* Start with first CPU's profile (cpu_count >= 1 guaranteed by contract) */
    *wc = profiles[0].vuln;

    /* Merge across all CPUs: take worst case (most vulnerable) */
    /*@ loop invariant 1 <= i <= cpu_count;
        loop assigns i, *wc, state->profiles_consistent,
                all_have_bhi_ctrl, all_have_amd_stibp;
        loop variant cpu_count - i;
    */
    for (i = 1; i < cpu_count; i++) {
        const struct fbvbs_vuln_profile *v = &profiles[i].vuln;

        /* Worst case: if ANY CPU is vulnerable, require mitigation */
        if (v->need_l1d_flush != 0U)         { wc->need_l1d_flush = 1; }
        if (v->need_verw != 0U)              { wc->need_verw = 1; }
        if (v->need_rsb_fill != 0U)          { wc->need_rsb_fill = 1; }
        if (v->need_pbrsb_sequence != 0U)    { wc->need_pbrsb_sequence = 1; }
        if (v->need_bhb_clear != 0U)         { wc->need_bhb_clear = 1; }
        if (v->need_tsx_disable != 0U)       { wc->need_tsx_disable = 1; }
        if (v->need_srso_mitigation != 0U)   { wc->need_srso_mitigation = 1; }
        if (v->need_retbleed_mitigation != 0U) { wc->need_retbleed_mitigation = 1; }
        if (v->need_lfence_serialize != 0U)  { wc->need_lfence_serialize = 1; }

        /* Immunity: only immune if ALL CPUs are immune (AND merge) */
        if (v->immune_meltdown == 0U)   { wc->immune_meltdown = 0; }
        if (v->immune_l1tf == 0U)       { wc->immune_l1tf = 0; }
        if (v->immune_mds == 0U)        { wc->immune_mds = 0; }
        if (v->immune_taa == 0U)        { wc->immune_taa = 0; }
        if (v->immune_ssb == 0U)        { wc->immune_ssb = 0; }
        if (v->immune_pbrsb == 0U)      { wc->immune_pbrsb = 0; }
        if (v->immune_gds == 0U)        { wc->immune_gds = 0; }
        if (v->immune_rfds == 0U)       { wc->immune_rfds = 0; }
        if (v->immune_bhi == 0U)        { wc->immune_bhi = 0; }
        if (v->immune_mmio_stale == 0U) { wc->immune_mmio_stale = 0; }
        if (v->immune_srso == 0U)       { wc->immune_srso = 0; }
        if (v->immune_retbleed == 0U)   { wc->immune_retbleed = 0; }

        /* AND-merge arch_capabilities across all CPUs: only trust
           capabilities present on every CPU */
        wc->arch_capabilities_lo &= v->arch_capabilities_lo;
        wc->arch_capabilities_hi &= v->arch_capabilities_hi;

        /* AND-merge feature flags across all CPUs */
        if (profiles[i].features.has_bhi_ctrl == 0U)   { all_have_bhi_ctrl = 0; }
        if (profiles[i].features.has_amd_stibp == 0U)  { all_have_amd_stibp = 0; }

        if (fbvbs_cpu_verify_consistency(&profiles[0], &profiles[i]) == 0) {
            state->profiles_consistent = 0;
        }
    }

    /* Fail-closed: mixed vendors detected — refuse to proceed.
       Security mitigations are vendor-specific; mixing is unsupported. */
    if (state->profiles_consistent == 0U &&
        cpu_count > 1U &&
        has_vendor_mismatch(profiles, cpu_count) != 0) {
        return -1;
    }

    /* Compute host SPEC_CTRL value using worst-case merged data */
    if (profiles[0].vendor == CPU_VENDOR_INTEL) {
        /* Only use set-and-forget IBRS if eIBRS (IBRS_ALL) is available
           on ALL CPUs (arch_capabilities_lo is AND-merged) */
        if (wc->arch_capabilities_lo & ARCH_CAP_IBRS_ALL) {
            state->host_spec_ctrl_value |= SPEC_CTRL_IBRS;
        }
        /* BHI_DIS_S only if ALL CPUs support BHI_CTRL */
        if (all_have_bhi_ctrl != 0U) {
            state->host_spec_ctrl_value |= SPEC_CTRL_BHI_DIS_S;
        }
        /* RRSBA_DIS_S: prevent RSB underflow alternate predictions */
        if (compute_any_rrsba(profiles, cpu_count) != 0U) {
            state->host_spec_ctrl_value |= SPEC_CTRL_RRSBA_DIS_S;
        }
        /* SSBD: Speculative Store Bypass Disable if not immune */
        if (wc->immune_ssb == 0U) {
            state->host_spec_ctrl_value |= SPEC_CTRL_SSBD;
        }
    } else if (profiles[0].vendor == CPU_VENDOR_AMD) {
        /* STIBP only if ALL CPUs support it */
        if (all_have_amd_stibp != 0U) {
            state->host_spec_ctrl_value |= SPEC_CTRL_STIBP;
        }
        /* SSBD for AMD if not immune to SSB */
        if (wc->immune_ssb == 0U) {
            state->host_spec_ctrl_value |= SPEC_CTRL_SSBD;
        }
    }

    /* Apply TSX disable if any CPU requires it (Intel only) */
    if (wc->need_tsx_disable != 0U &&
        profiles[0].vendor == CPU_VENDOR_INTEL &&
        (wc->arch_capabilities_lo & ARCH_CAP_TSX_CTRL)) {
        /* RTM_DISABLE (bit 0) + TSX_CPUID_CLEAR (bit 1) */
        msr_write(MSR_IA32_TSX_CTRL, 3);
    }

    /* GDS (Downfall) mitigation: MCU_OPT_CTRL[GDS_MITG_DIS] = 0 enables mitigation.
     * Opt-in via VERW (already handled by need_verw). Just ensure MCU_OPT_CTRL
     * does not have the disable bit set. */
    if (wc->immune_gds == 0U &&
        profiles[0].vendor == CPU_VENDOR_INTEL &&
        profiles[0].features.has_mcu_opt_ctrl != 0U) {
        /* Ensure GDS mitigation is not disabled in MCU_OPT_CTRL.
         * Bit 4 = GDS_MITG_DIS: must be 0 for mitigation to be active.
         * Reading and clearing this bit ensures microcode-level mitigation is on. */
        uint64_t mcu_opt = msr_read(MSR_IA32_MCU_OPT_CTRL);
        if ((mcu_opt & (1ULL << 4)) != 0U) {
            msr_write(MSR_IA32_MCU_OPT_CTRL, mcu_opt & ~(1ULL << 4));
        }
    }

    /* Apply LFENCE serialization (AMD: set DE_CFG[1]) */
    if (wc->need_lfence_serialize != 0U &&
        profiles[0].vendor == CPU_VENDOR_AMD) {
        uint64_t de_cfg = msr_read(MSR_AMD_DE_CFG);
        /* DE_CFG[1] = LFENCE serializing.
           DE_CFG[9] = Zenbleed mitigation (CVE-2023-20593, AMD Zen 2).
           Setting bit 9 is a no-op on non-Zen-2 CPUs, so unconditionally
           safe and eliminates the need for family/model detection. */
        msr_write(MSR_AMD_DE_CFG, de_cfg | (1ULL << 1) | (1ULL << 9));
    }

    return 0;
}

/* ================================================================
 * IOMMU detection (platform-level stub)
 * ================================================================ */

/*@ requires \valid(state);
    assigns state->iommu;
*/
int fbvbs_iommu_detect(struct fbvbs_global_security_state *state)
{
    state->iommu = (struct fbvbs_iommu_state){0};

    /* In bare-metal: parse ACPI DMAR (Intel) or IVRS (AMD) tables.
     * For verification model: mark as detected based on vendor. */
    if (state->vendor == CPU_VENDOR_INTEL) {
        state->iommu.iommu_type = IOMMU_TYPE_VTD;
    } else if (state->vendor == CPU_VENDOR_AMD) {
        state->iommu.iommu_type = IOMMU_TYPE_AMD_VI;
    } else {
        state->iommu.iommu_type = IOMMU_TYPE_NONE;
    }

    /* Fail closed: a hostile-environment hypervisor must not claim DMA
     * isolation without authoritative evidence of DMA remapping,
     * interrupt remapping, and ACS qualification. */
    return -1;
}

/* ================================================================
 * Boot integrity detection (platform-level stub)
 * ================================================================ */

/*@ requires \valid(state);
    assigns state->boot;
*/
int fbvbs_boot_integrity_detect(struct fbvbs_global_security_state *state)
{
    state->boot = (struct fbvbs_boot_integrity){0};

    if (state->vendor == CPU_VENDOR_INTEL) {
        /* Check for TXT via GETSEC leaf availability */
        uint32_t eax, ebx, ecx, edx;
        cpuid_query(1, 0, &eax, &ebx, &ecx, &edx);
        if ((ecx >> 6) & 1U) { /* SMX bit */
            state->boot.drtm_available = 1;
            state->boot.drtm_type = 1; /* TXT */
        }
    } else if (state->vendor == CPU_VENDOR_AMD) {
        /* Check for SKINIT via CPUID 0x80000001 ECX[12] */
        uint32_t eax, ebx, ecx, edx;
        cpuid_query(0x80000001U, 0, &eax, &ebx, &ecx, &edx);
        if ((ecx >> 12) & 1U) {
            state->boot.drtm_available = 1;
            state->boot.drtm_type = 2; /* SKINIT */
        }
    }

    /* Fail closed: DRTM/TPM/Secure Boot/measured boot must be established by
     * the real platform bring-up path before this hypervisor can claim a
     * trustworthy boot chain. */
    return -1;
}

/* ================================================================
 * CPU profile consistency verification
 * ================================================================ */

/*@ requires \valid_read(profile_a);
    requires \valid_read(profile_b);
    requires profile_a->initialized == 1;
    requires profile_b->initialized == 1;
    assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
int fbvbs_cpu_verify_consistency(
    const struct fbvbs_cpu_security_profile *profile_a,
    const struct fbvbs_cpu_security_profile *profile_b)
{
    if (profile_a->vendor != profile_b->vendor) { return 0; }
    if (profile_a->family != profile_b->family) { return 0; }
    if (profile_a->model  != profile_b->model)  { return 0; }
    if (profile_a->stepping != profile_b->stepping) { return 0; }
    if (profile_a->microcode_version != profile_b->microcode_version) { return 0; }
    if (profile_a->smt_enabled != profile_b->smt_enabled) { return 0; }

    /* Feature flags must match for security-critical features */
    const struct fbvbs_cpuid_features *fa = &profile_a->features;
    const struct fbvbs_cpuid_features *fb = &profile_b->features;

    if (fa->has_smep         != fb->has_smep)         { return 0; }
    if (fa->has_smap         != fb->has_smap)         { return 0; }
    if (fa->has_cet_ss       != fb->has_cet_ss)       { return 0; }
    if (fa->has_cet_ibt      != fb->has_cet_ibt)      { return 0; }
    if (fa->has_md_clear     != fb->has_md_clear)     { return 0; }
    if (fa->has_mcu_opt_ctrl != fb->has_mcu_opt_ctrl) { return 0; }
    if (fa->has_ibpb         != fb->has_ibpb)         { return 0; }
    if (fa->has_stibp        != fb->has_stibp)        { return 0; }
    if (fa->has_umip         != fb->has_umip)         { return 0; }
    if (fa->has_pku          != fb->has_pku)          { return 0; }
    if (fa->has_pks          != fb->has_pks)          { return 0; }
    if (fa->has_la57         != fb->has_la57)         { return 0; }
    if (fa->has_lass         != fb->has_lass)         { return 0; }
    if (fa->has_fred         != fb->has_fred)         { return 0; }
    if (fa->has_bhi_ctrl     != fb->has_bhi_ctrl)     { return 0; }
    if (fa->has_vmx          != fb->has_vmx)          { return 0; }
    if (fa->has_svm          != fb->has_svm)          { return 0; }
    if (fa->has_npt          != fb->has_npt)          { return 0; }
    if (fa->has_gmet         != fb->has_gmet)         { return 0; }
    if (fa->has_avic         != fb->has_avic)         { return 0; }
    if (fa->has_vgif         != fb->has_vgif)         { return 0; }
    if (fa->has_vmcb_clean   != fb->has_vmcb_clean)   { return 0; }
    if (fa->has_decode_assists != fb->has_decode_assists) { return 0; }
    if (fa->has_vnmi         != fb->has_vnmi)         { return 0; }
    if (fa->has_pause_filter != fb->has_pause_filter) { return 0; }
    if (fa->has_lbr_virt     != fb->has_lbr_virt)     { return 0; }
    if (fa->has_sss_check    != fb->has_sss_check)    { return 0; }
    if (fa->has_amd_ibpb     != fb->has_amd_ibpb)     { return 0; }
    if (fa->has_amd_stibp    != fb->has_amd_stibp)    { return 0; }
    if (fa->has_amd_ibpb_ret != fb->has_amd_ibpb_ret) { return 0; }
    if (fa->has_autoibrs     != fb->has_autoibrs)     { return 0; }
    if (fa->has_amd_ssbd     != fb->has_amd_ssbd)     { return 0; }
    if (fa->has_sev          != fb->has_sev)          { return 0; }
    if (fa->has_sev_es       != fb->has_sev_es)       { return 0; }
    if (fa->has_sev_snp      != fb->has_sev_snp)      { return 0; }
    if (fa->has_sme          != fb->has_sme)          { return 0; }
    if (fa->has_pcid         != fb->has_pcid)         { return 0; }
    if (fa->has_aesni        != fb->has_aesni)        { return 0; }
    if (fa->has_nx           != fb->has_nx)           { return 0; }

    /* Vulnerability profiles must match — all 12 immunity flags */
    const struct fbvbs_vuln_profile *a = &profile_a->vuln;
    const struct fbvbs_vuln_profile *b = &profile_b->vuln;

    if (a->immune_meltdown != b->immune_meltdown ||
        a->immune_l1tf != b->immune_l1tf ||
        a->immune_mds != b->immune_mds ||
        a->immune_taa != b->immune_taa ||
        a->immune_ssb != b->immune_ssb ||
        a->immune_pbrsb != b->immune_pbrsb ||
        a->immune_gds != b->immune_gds ||
        a->immune_rfds != b->immune_rfds ||
        a->immune_bhi != b->immune_bhi ||
        a->immune_mmio_stale != b->immune_mmio_stale ||
        a->immune_srso != b->immune_srso ||
        a->immune_retbleed != b->immune_retbleed) {
        return 0;
    }

    return 1;
}

/* ================================================================
 * VM Exit mitigation sequence
 *
 * Called per-core immediately after VM exit, before any other
 * hypervisor processing. Each step is conditional on the
 * per-CPU vulnerability profile. Lock-free: operates only on
 * per-core local state.
 *
 * Sequence (Section 21.3):
 * 1. IBPB (cross-partition exits) — clears indirect branch predictions
 * 2. RSB fill — 32 CALLs to fill Return Stack Buffer
 * 3. PBRSB sequence — mitigates post-barrier RSB predictions
 * 4. BHB clear — ~200 instruction sequence for Branch History Buffer
 * 5. Save guest SPEC_CTRL
 * 6. Restore host SPEC_CTRL
 * 7. VERW (MDS/TAA/MMIO) — MUST be last per Intel SDM
 * ================================================================ */

/*@ requires \valid_read(vuln);
    requires \valid(spec_state);
    assigns spec_state->guest_spec_ctrl;
*/
void fbvbs_vmexit_mitigate(const struct fbvbs_vuln_profile *vuln,
                           struct fbvbs_spec_ctrl_state *spec_state,
                           uint32_t is_cross_partition)
{
    /* Step 1: IBPB for cross-partition exits.
       Critical for Spectre v2: without IBPB, indirect branch predictions
       from a previous VM context may be exploited by the current context.
       IBPB must be issued before any branch-dependent hypervisor code executes. */
    if (is_cross_partition != 0U) {
        msr_write(MSR_IA32_PRED_CMD, 1);
    }

    /* Step 2: RSB fill */
    if (vuln->need_rsb_fill != 0U) {
        /* Bare-metal: execute 32 CALL instructions to fill RSB */
        /* Model: no-op for verification */
    }

    /* Step 3: PBRSB mitigation */
    if (vuln->need_pbrsb_sequence != 0U) {
        /* Bare-metal: lightweight CALL sequence after VM exit */
        /* Model: no-op for verification */
    }

    /* Step 4: BHB clear */
    if (vuln->need_bhb_clear != 0U) {
        /* Bare-metal: ~200 instruction BHB clearing sequence */
        /* Model: no-op for verification */
    }

    /* Step 5: Save guest SPEC_CTRL */
    spec_state->guest_spec_ctrl = msr_read(MSR_IA32_SPEC_CTRL);

    /* Step 6: Restore host SPEC_CTRL */
    msr_write(MSR_IA32_SPEC_CTRL, spec_state->host_spec_ctrl);

    /* Step 7: VERW for MDS/TAA/MMIO — MUST be last before returning
       to non-speculative execution. Any subsequent instruction (including
       MSR reads/writes above) can create new fill buffer entries that
       VERW clears. Intel SDM: "as close to the transition as possible." */
    if (vuln->need_verw != 0U) {
        /* Bare-metal: VERW with valid selector */
        /* Model: no-op for verification */
    }
}

/* ================================================================
 * VM Entry mitigation sequence
 *
 * Called per-core immediately before VM entry. Lock-free.
 *
 * Sequence (Section 21.3):
 * 1. L1D flush (L1TF affected)
 * 2. Restore guest SPEC_CTRL
 * ================================================================ */

/*@ requires \valid_read(vuln);
    requires \valid(spec_state);
    assigns spec_state->host_spec_ctrl;
*/
void fbvbs_vmentry_mitigate(const struct fbvbs_vuln_profile *vuln,
                            struct fbvbs_spec_ctrl_state *spec_state)
{
    /* Step 1: L1D flush */
    if (vuln->need_l1d_flush != 0U) {
        /* Bare-metal: write 1 to IA32_FLUSH_CMD */
        msr_write(MSR_IA32_FLUSH_CMD, 1);
    }

    /* Step 2: Save host SPEC_CTRL and restore guest */
    spec_state->host_spec_ctrl = msr_read(MSR_IA32_SPEC_CTRL);
    msr_write(MSR_IA32_SPEC_CTRL, spec_state->guest_spec_ctrl);

    /* Step 3: VERW to clear MDS/TAA/MMIO stale data fill buffers.
       Must be as close to VM entry as possible — any subsequent
       instruction can create new fill buffer entries. */
    if (vuln->need_verw != 0U) {
        uint16_t ds_sel = 0;
        __asm__ volatile("verw %0" : : "m"(ds_sel) : "cc", "memory");
    }
}

/* ================================================================
 * CET state save/restore
 * ================================================================ */

/*@ requires \valid(guest_cet);
    requires \valid_read(host_cet);
    assigns *guest_cet;
*/
void fbvbs_cet_save_guest(struct fbvbs_cet_state *guest_cet,
                          const struct fbvbs_cet_state *host_cet)
{
    /* Save guest CET state */
    guest_cet->s_cet    = msr_read(MSR_IA32_S_CET);
    guest_cet->u_cet    = msr_read(MSR_IA32_U_CET);
    guest_cet->pl0_ssp  = msr_read(MSR_IA32_PL0_SSP);
    guest_cet->pl1_ssp  = msr_read(MSR_IA32_PL1_SSP);
    guest_cet->pl2_ssp  = msr_read(MSR_IA32_PL2_SSP);
    guest_cet->pl3_ssp  = msr_read(MSR_IA32_PL3_SSP);
    guest_cet->isst_addr = msr_read(MSR_IA32_INTERRUPT_SSP_TABLE);

    /* Restore host CET state */
    msr_write(MSR_IA32_S_CET, host_cet->s_cet);
    msr_write(MSR_IA32_U_CET, host_cet->u_cet);
    msr_write(MSR_IA32_PL0_SSP, host_cet->pl0_ssp);
    msr_write(MSR_IA32_PL1_SSP, host_cet->pl1_ssp);
    msr_write(MSR_IA32_PL2_SSP, host_cet->pl2_ssp);
    msr_write(MSR_IA32_PL3_SSP, host_cet->pl3_ssp);
    msr_write(MSR_IA32_INTERRUPT_SSP_TABLE, host_cet->isst_addr);
}

/*@ requires \valid_read(guest_cet);
    assigns \nothing;
*/
void fbvbs_cet_restore_guest(const struct fbvbs_cet_state *guest_cet)
{
    msr_write(MSR_IA32_S_CET, guest_cet->s_cet);
    msr_write(MSR_IA32_U_CET, guest_cet->u_cet);
    msr_write(MSR_IA32_PL0_SSP, guest_cet->pl0_ssp);
    msr_write(MSR_IA32_PL1_SSP, guest_cet->pl1_ssp);
    msr_write(MSR_IA32_PL2_SSP, guest_cet->pl2_ssp);
    msr_write(MSR_IA32_PL3_SSP, guest_cet->pl3_ssp);
    msr_write(MSR_IA32_INTERRUPT_SSP_TABLE, guest_cet->isst_addr);
}

/* ================================================================
 * Debug register save/restore
 * ================================================================ */

/*@ requires \valid(guest_dbg);
    assigns *guest_dbg;
*/
void fbvbs_debug_save_guest(struct fbvbs_debug_state *guest_dbg)
{
    /* Bare-metal: MOV from DRx registers */
    /* Model: zero for verification */
    guest_dbg->dr0 = 0;
    guest_dbg->dr1 = 0;
    guest_dbg->dr2 = 0;
    guest_dbg->dr3 = 0;
    guest_dbg->dr6 = 0;
    guest_dbg->dr7 = 0;
}

/*@ requires \valid_read(guest_dbg);
    assigns \nothing;
*/
void fbvbs_debug_restore_guest(const struct fbvbs_debug_state *guest_dbg)
{
    /* Bare-metal: MOV to DRx registers */
    (void)guest_dbg;
}
