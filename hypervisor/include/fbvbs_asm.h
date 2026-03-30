/*
 * FBVBS Assembly Backend Interface (Phase 1-12)
 *
 * Centralizes all x86_64 assembly operations required by the
 * microhypervisor into a single header. Each operation has:
 *   - A C inline function with __asm__ volatile for bare-metal
 *   - A #ifdef __FRAMAC__ model path for formal verification
 *   - ACSL contracts where applicable
 *
 * Categories (matching Phase 1-12 roadmap items):
 *   A. VMCS operations (VMWRITE/VMREAD/VMCLEAR/VMPTRLD/VMLAUNCH/VMRESUME)
 *   B. MSR operations (RDMSR/WRMSR)
 *   C. CPUID (feature detection)
 *   D. CR operations (CR0/CR3/CR4 read/write)
 *   E. Page table operations (INVLPG, INVEPT, INVVPID)
 *   F. Speculation barriers (LFENCE, MFENCE, SFENCE, SERIALIZE)
 *   G. Privileged I/O (INB/OUTB for UART)
 *   H. Halt/pause (HLT, PAUSE, CLI, STI)
 *   I. IDT/GDT/TSS (LIDT, LGDT, LTR)
 *   J. TLB (INVLPG, INVPCID)
 *
 * PRODUCTION NOTE: In bare-metal deployment, these inline functions
 * compile to the actual privileged instructions. The model paths
 * (under __FRAMAC__) provide deterministic behavior for WP proofs.
 *
 * Usage: Include this header in source files that need privileged
 * operations. It replaces scattered inline asm and provides a
 * single audit surface for assembly correctness.
 */

#ifndef FBVBS_ASM_H
#define FBVBS_ASM_H

#include <stdint.h>

/* ================================================================
 * A. VMCS Operations
 * ================================================================ */

/*@ assigns \nothing;
    ensures \result == 0 || \result == -1;
*/
static inline int fbvbs_asm_vmxon(uint64_t vmxon_region_phys) {
#ifdef __FRAMAC__
    (void)vmxon_region_phys;
    return 0;
#elif defined(__x86_64__)
    uint8_t err;
    __asm__ volatile("vmxon %1; setna %0"
                     : "=qm"(err)
                     : "m"(vmxon_region_phys)
                     : "cc", "memory");
    return err ? -1 : 0;
#else
    (void)vmxon_region_phys;
    return -1;
#endif
}

/*@ assigns \nothing; */
static inline void fbvbs_asm_vmxoff(void) {
#if defined(__x86_64__) && !defined(__FRAMAC__)
    __asm__ volatile("vmxoff" : : : "cc", "memory");
#endif
}

/*@ assigns \nothing;
    ensures \result == 0 || \result == -1;
*/
static inline int fbvbs_asm_vmclear(uint64_t vmcs_phys) {
#ifdef __FRAMAC__
    (void)vmcs_phys;
    return 0;
#elif defined(__x86_64__)
    uint8_t err;
    __asm__ volatile("vmclear %1; setna %0"
                     : "=qm"(err)
                     : "m"(vmcs_phys)
                     : "cc", "memory");
    return err ? -1 : 0;
#else
    (void)vmcs_phys;
    return -1;
#endif
}

/*@ assigns \nothing;
    ensures \result == 0 || \result == -1;
*/
static inline int fbvbs_asm_vmptrld(uint64_t vmcs_phys) {
#ifdef __FRAMAC__
    (void)vmcs_phys;
    return 0;
#elif defined(__x86_64__)
    uint8_t err;
    __asm__ volatile("vmptrld %1; setna %0"
                     : "=qm"(err)
                     : "m"(vmcs_phys)
                     : "cc", "memory");
    return err ? -1 : 0;
#else
    (void)vmcs_phys;
    return -1;
#endif
}

/*@ assigns \nothing;
    ensures \result == 0 || \result == -1;
*/
static inline int fbvbs_asm_vmwrite(uint64_t field, uint64_t value) {
#ifdef __FRAMAC__
    (void)field;
    (void)value;
    return 0;
#elif defined(__x86_64__)
    uint8_t err;
    __asm__ volatile("vmwrite %2, %1; setna %0"
                     : "=qm"(err)
                     : "r"(field), "rm"(value)
                     : "cc", "memory");
    return err ? -1 : 0;
#else
    (void)field;
    (void)value;
    return -1;
#endif
}

/*@ requires value == \null || \valid(value);
    assigns *value;
    ensures \result == 0 || \result == -1;
*/
static inline int fbvbs_asm_vmread(uint64_t field, uint64_t *value) {
#ifdef __FRAMAC__
    (void)field;
    if (value) *value = 0;
    return 0;
#elif defined(__x86_64__)
    uint8_t err;
    uint64_t val;
    __asm__ volatile("vmread %2, %1; setna %0"
                     : "=qm"(err), "=rm"(val)
                     : "r"(field)
                     : "cc");
    if (value) *value = val;
    return err ? -1 : 0;
#else
    (void)field;
    if (value) *value = 0;
    return -1;
#endif
}

/* ================================================================
 * B. MSR Operations
 * ================================================================ */

/*@ assigns \nothing;
*/
static inline uint64_t fbvbs_asm_rdmsr(uint32_t msr) {
#ifdef __FRAMAC__
    (void)msr;
    return 0;
#elif defined(__x86_64__)
    uint32_t lo, hi;
    __asm__ volatile("rdmsr"
                     : "=a"(lo), "=d"(hi)
                     : "c"(msr)
                     : "memory");
    return ((uint64_t)hi << 32) | lo;
#else
    (void)msr;
    return 0;
#endif
}

static inline void fbvbs_asm_wrmsr(uint32_t msr, uint64_t value) {
#if defined(__x86_64__) && !defined(__FRAMAC__)
    uint32_t lo = (uint32_t)(value & 0xFFFFFFFFU);
    uint32_t hi = (uint32_t)(value >> 32U);
    __asm__ volatile("wrmsr"
                     : : "c"(msr), "a"(lo), "d"(hi)
                     : "memory");
#else
    (void)msr;
    (void)value;
#endif
}

/* ================================================================
 * C. CPUID
 * ================================================================ */

/*@ requires \valid(eax);
    requires \valid(ebx);
    requires \valid(ecx);
    requires \valid(edx);
    requires \separated(eax, ebx, ecx, edx);
    assigns *eax, *ebx, *ecx, *edx;
*/
static inline void fbvbs_asm_cpuid(
    uint32_t leaf, uint32_t subleaf,
    uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx)
{
#ifdef __FRAMAC__
    (void)leaf;
    (void)subleaf;
    if (eax) *eax = 0;
    if (ebx) *ebx = 0;
    if (ecx) *ecx = 0;
    if (edx) *edx = 0;
#elif defined(__x86_64__) || defined(__i386__)
    uint32_t a, b, c, d;
    __asm__ volatile("cpuid"
                     : "=a"(a), "=b"(b), "=c"(c), "=d"(d)
                     : "0"(leaf), "2"(subleaf)
                     : "memory");
    if (eax) *eax = a;
    if (ebx) *ebx = b;
    if (ecx) *ecx = c;
    if (edx) *edx = d;
#else
    (void)leaf;
    (void)subleaf;
    if (eax) *eax = 0;
    if (ebx) *ebx = 0;
    if (ecx) *ecx = 0;
    if (edx) *edx = 0;
#endif
}

/* ================================================================
 * D. CR Operations
 * ================================================================ */

static inline uint64_t fbvbs_asm_read_cr0(void) {
#if defined(__x86_64__) && !defined(__FRAMAC__)
    uint64_t val;
    __asm__ volatile("mov %%cr0, %0" : "=r"(val));
    return val;
#else
    return 0;
#endif
}

static inline void fbvbs_asm_write_cr0(uint64_t val) {
#if defined(__x86_64__) && !defined(__FRAMAC__)
    __asm__ volatile("mov %0, %%cr0" : : "r"(val) : "memory");
#else
    (void)val;
#endif
}

static inline uint64_t fbvbs_asm_read_cr3(void) {
#if defined(__x86_64__) && !defined(__FRAMAC__)
    uint64_t val;
    __asm__ volatile("mov %%cr3, %0" : "=r"(val));
    return val;
#else
    return 0;
#endif
}

static inline void fbvbs_asm_write_cr3(uint64_t val) {
#if defined(__x86_64__) && !defined(__FRAMAC__)
    __asm__ volatile("mov %0, %%cr3" : : "r"(val) : "memory");
#else
    (void)val;
#endif
}

static inline uint64_t fbvbs_asm_read_cr4(void) {
#if defined(__x86_64__) && !defined(__FRAMAC__)
    uint64_t val;
    __asm__ volatile("mov %%cr4, %0" : "=r"(val));
    return val;
#else
    return 0;
#endif
}

static inline void fbvbs_asm_write_cr4(uint64_t val) {
#if defined(__x86_64__) && !defined(__FRAMAC__)
    __asm__ volatile("mov %0, %%cr4" : : "r"(val) : "memory");
#else
    (void)val;
#endif
}

/* ================================================================
 * E. TLB / Translation Invalidation
 * ================================================================ */

static inline void fbvbs_asm_invlpg(uint64_t addr) {
#if defined(__x86_64__) && !defined(__FRAMAC__)
    __asm__ volatile("invlpg (%0)" : : "r"(addr) : "memory");
#else
    (void)addr;
#endif
}

static inline int fbvbs_asm_invept(uint64_t type, uint64_t eptp) {
#ifdef __FRAMAC__
    (void)type;
    (void)eptp;
    return 0;
#elif defined(__x86_64__)
    struct { uint64_t eptp; uint64_t reserved; } desc = { eptp, 0 };
    uint8_t err;
    __asm__ volatile("invept %1, %2; setna %0"
                     : "=qm"(err)
                     : "m"(desc), "r"(type)
                     : "cc", "memory");
    return err ? -1 : 0;
#else
    (void)type;
    (void)eptp;
    return -1;
#endif
}

/* ================================================================
 * F. Speculation Barriers
 * ================================================================ */

static inline void fbvbs_asm_lfence(void) {
#if defined(__x86_64__) && !defined(__FRAMAC__)
    __asm__ volatile("lfence" : : : "memory");
#endif
}

static inline void fbvbs_asm_mfence(void) {
#if defined(__x86_64__) && !defined(__FRAMAC__)
    __asm__ volatile("mfence" : : : "memory");
#endif
}

static inline void fbvbs_asm_compiler_barrier(void) {
#ifdef __FRAMAC__
    return;
#else
    __asm__ volatile("" : : : "memory");
#endif
}

/*@ assigns \nothing;
    ensures \result == value;
*/
static inline uint32_t fbvbs_asm_observe_u32(uint32_t value) {
#ifdef __FRAMAC__
    return value;
#else
    __asm__ volatile("" : "+r"(value) : : "memory");
    return value;
#endif
}

/*@ assigns \nothing;
    ensures \result == value;
*/
static inline uint64_t fbvbs_asm_observe_u64(uint64_t value) {
#ifdef __FRAMAC__
    return value;
#else
    __asm__ volatile("" : "+r"(value) : : "memory");
    return value;
#endif
}

/* ================================================================
 * G. Privileged I/O (UART for early debug)
 * ================================================================ */

static inline void fbvbs_asm_outb(uint16_t port, uint8_t val) {
#if defined(__x86_64__) && !defined(__FRAMAC__)
    __asm__ volatile("outb %0, %1" : : "a"(val), "Nd"(port) : "memory");
#else
    (void)port;
    (void)val;
#endif
}

static inline uint8_t fbvbs_asm_inb(uint16_t port) {
#if defined(__x86_64__) && !defined(__FRAMAC__)
    uint8_t val;
    __asm__ volatile("inb %1, %0" : "=a"(val) : "Nd"(port) : "memory");
    return val;
#else
    (void)port;
    return 0;
#endif
}

/* ================================================================
 * H. CPU Control
 * ================================================================ */

static inline void fbvbs_asm_hlt(void) {
#if defined(__x86_64__) && !defined(__FRAMAC__)
    __asm__ volatile("hlt" : : : "memory");
#endif
}

static inline void fbvbs_asm_pause(void) {
#if defined(__x86_64__) && !defined(__FRAMAC__)
    __asm__ volatile("pause" : : : "memory");
#endif
}

static inline void fbvbs_asm_cli(void) {
#if defined(__x86_64__) && !defined(__FRAMAC__)
    __asm__ volatile("cli" : : : "memory");
#endif
}

static inline void fbvbs_asm_sti(void) {
#if defined(__x86_64__) && !defined(__FRAMAC__)
    __asm__ volatile("sti" : : : "memory");
#endif
}

/* ================================================================
 * I. Descriptor Table Operations
 * ================================================================ */

struct fbvbs_asm_desc_ptr {
    uint16_t limit;
    uint64_t base;
} __attribute__((packed));

static inline void fbvbs_asm_lidt(const struct fbvbs_asm_desc_ptr *idtr) {
#if defined(__x86_64__) && !defined(__FRAMAC__)
    __asm__ volatile("lidt %0" : : "m"(*idtr) : "memory");
#else
    (void)idtr;
#endif
}

static inline void fbvbs_asm_lgdt(const struct fbvbs_asm_desc_ptr *gdtr) {
#if defined(__x86_64__) && !defined(__FRAMAC__)
    __asm__ volatile("lgdt %0" : : "m"(*gdtr) : "memory");
#else
    (void)gdtr;
#endif
}

static inline void fbvbs_asm_ltr(uint16_t selector) {
#if defined(__x86_64__) && !defined(__FRAMAC__)
    __asm__ volatile("ltr %w0" : : "r"(selector) : "memory");
#else
    (void)selector;
#endif
}

/*@ assigns \result \from \nothing;
*/
static inline uint64_t fbvbs_asm_read_rsp(void) {
#if defined(__x86_64__) && !defined(__FRAMAC__)
    uint64_t value;
    __asm__ volatile("mov %%rsp, %0" : "=r"(value));
    return value;
#else
    return 0U;
#endif
}

/*@ assigns \result \from \nothing;
*/
static inline uint64_t fbvbs_asm_read_rflags(void) {
#if defined(__x86_64__) && !defined(__FRAMAC__)
    uint64_t value;
    __asm__ volatile("pushfq; popq %0" : "=r"(value) : : "memory");
    return value;
#else
    return 0x202U;
#endif
}

/* ================================================================
 * J. Entropy (RDRAND/RDSEED)
 *
 * These are defined in cpu_security.c with retry logic.
 * The raw instructions are here for reference:
 * ================================================================ */

static inline int fbvbs_asm_rdrand64_raw(uint64_t *val) {
#ifdef __FRAMAC__
    if (val) *val = 0xDEADBEEFCAFEBABEULL;
    return 0;
#elif defined(__x86_64__)
    unsigned char ok;
    uint64_t v;
    __asm__ volatile("rdrand %0; setc %1"
                     : "=r"(v), "=qm"(ok)
                     : : "cc");
    if (val) *val = v;
    return ok ? 0 : -1;
#else
    if (val) *val = 0;
    return -1;
#endif
}

static inline int fbvbs_asm_rdseed64_raw(uint64_t *val) {
#ifdef __FRAMAC__
    if (val) *val = 0xFEEDFACE12345678ULL;
    return 0;
#elif defined(__x86_64__)
    unsigned char ok;
    uint64_t v;
    __asm__ volatile("rdseed %0; setc %1"
                     : "=r"(v), "=qm"(ok)
                     : : "cc");
    if (val) *val = v;
    return ok ? 0 : -1;
#else
    if (val) *val = 0;
    return -1;
#endif
}

/* ================================================================
 * K. VERW (MDS/TAA/MMIO/RFDS mitigation)
 *
 * Must be placed as close to VMRESUME/VMLAUNCH as possible.
 * In production, this is in the same asm block as VM entry.
 * ================================================================ */

/*@ assigns \nothing; */
static inline void fbvbs_asm_verw(void) {
#if defined(__x86_64__) && !defined(__FRAMAC__)
    uint16_t ds_sel = 0;
    __asm__ volatile("verw %0" : : "m"(ds_sel) : "cc", "memory");
#endif
}

/* ================================================================
 * M. Descriptor table register reads (SGDT/SIDT)
 * ================================================================ */

struct fbvbs_asm_dt_reg {
    uint64_t base;
    uint16_t limit;
};

/*@ requires \valid(out);
    assigns *out;
*/
static inline void fbvbs_asm_sgdt(struct fbvbs_asm_dt_reg *out) {
#if defined(__x86_64__) && !defined(__FRAMAC__)
    uint8_t buf[10];
    __asm__ volatile("sgdt %0" : "=m"(buf));
    out->limit = (uint16_t)((uint16_t)buf[0] | ((uint16_t)buf[1] << 8));
    uint64_t base = 0;
    for (int i = 0; i < 8; i++) {
        base |= (uint64_t)buf[2 + i] << (i * 8);
    }
    out->base = base;
#else
    out->base = 0;
    out->limit = 0;
#endif
}

/*@ requires \valid(out);
    assigns *out;
*/
static inline void fbvbs_asm_sidt(struct fbvbs_asm_dt_reg *out) {
#if defined(__x86_64__) && !defined(__FRAMAC__)
    uint8_t buf[10];
    __asm__ volatile("sidt %0" : "=m"(buf));
    out->limit = (uint16_t)((uint16_t)buf[0] | ((uint16_t)buf[1] << 8));
    uint64_t base = 0;
    for (int i = 0; i < 8; i++) {
        base |= (uint64_t)buf[2 + i] << (i * 8);
    }
    out->base = base;
#else
    out->base = 0;
    out->limit = 0;
#endif
}

/* ================================================================
 * N. Assembly VMX entry points (defined in boot.S)
 *
 * These are only available on bare-metal x86_64 builds.
 * ================================================================ */

#if defined(__x86_64__) && !defined(__FRAMAC__) && !defined(__STDC_HOSTED__)
extern int fbvbs_vmlaunch(void);
extern int fbvbs_vmresume(void);
extern uint64_t fbvbs_get_vmexit_handler_rip(void);
extern uint64_t fbvbs_get_vmx_stack_top(void);
extern uint64_t fbvbs_get_boot_tss_base(void);
#endif

#endif /* FBVBS_ASM_H */
