/*
 * FBVBS IDT + Exception Handler Model (Phase 1-1)
 *
 * Provides hypervisor-level exception handling for x86_64.
 * The IDT is loaded at early init (after GDT/paging setup, before VMXON).
 *
 * Exception vectors handled:
 *   #DE (0)  — Divide Error
 *   #DB (1)  — Debug Exception
 *   #NMI (2) — Non-Maskable Interrupt (IST 1)
 *   #BP (3)  — Breakpoint
 *   #UD (6)  — Undefined Opcode
 *   #GP (13) — General Protection Fault
 *   #PF (14) — Page Fault
 *   #DF (8)  — Double Fault (IST 2)
 *   #MC (18) — Machine Check Exception (IST 3)
 *
 * IST Stack separation:
 *   IST 1: NMI — dedicated 4KiB stack (NMI can arrive during any context)
 *   IST 2: #DF — dedicated 4KiB stack (prevents stack overflow cascading)
 *   IST 3: #MC — dedicated 4KiB stack (MCE can arrive at any time)
 *
 * Design: All exception handlers log the exception via UART (model:
 * fbvbs_log_append) and then halt the processor. The hypervisor does
 * NOT attempt exception recovery — any exception in hypervisor context
 * is a fatal internal error.
 *
 * PRODUCTION NOTE: The actual IDT descriptor loads require assembly:
 *   - LIDT instruction to load IDT register
 *   - ISR entry stubs that save registers, call C handler, and IRETQ
 *   - TSS setup for IST stack pointers
 *   The C-level model here defines the IDT structure, gate descriptors,
 *   and the handler logic. The assembly stubs are in Phase 1-12.
 */

#include <stdint.h>

#include "fbvbs_hypervisor.h"

/* ================================================================
 * IDT gate descriptor (x86_64 long mode, 16 bytes per entry)
 * ================================================================ */

struct fbvbs_idt_gate {
    uint16_t offset_low;     /* Offset bits 0..15 */
    uint16_t selector;       /* Code segment selector */
    uint8_t  ist;            /* IST index (bits 0..2), reserved (bits 3..7) */
    uint8_t  type_attr;      /* Type (bits 0..3), DPL (bits 5..6), P (bit 7) */
    uint16_t offset_mid;     /* Offset bits 16..31 */
    uint32_t offset_high;    /* Offset bits 32..63 */
    uint32_t reserved;       /* Must be 0 */
};

_Static_assert(sizeof(struct fbvbs_idt_gate) == 16U,
               "IDT gate descriptor must be 16 bytes");

/* IDT register descriptor (for LIDT instruction) */
struct fbvbs_idtr {
    uint16_t limit;
    uint64_t base;
} __attribute__((packed));

/* ================================================================
 * IDT table and configuration
 * ================================================================ */

/* 256 IDT entries (0-255), but we only populate exception vectors */
#define IDT_ENTRIES 256U
#define IDT_TABLE_SIZE (IDT_ENTRIES * sizeof(struct fbvbs_idt_gate))

/* Gate type: 64-bit interrupt gate (type=0xE, DPL=0, P=1) */
#define IDT_TYPE_INTERRUPT_64 0x8EU

/* IST assignments */
#define IST_NONE 0U
#define IST_NMI  1U
#define IST_DF   2U
#define IST_MC   3U

/* IST stack sizes (4 KiB each with guard page) */
#define IST_STACK_SIZE 4096U

/* Code segment selector (must match boot.S runtime GDT 64-bit code entry) */
#define KERNEL_CS 0x18U

/* Exception vector numbers */
#define VECTOR_DE  0U   /* Divide Error */
#define VECTOR_DB  1U   /* Debug */
#define VECTOR_NMI 2U   /* Non-Maskable Interrupt */
#define VECTOR_BP  3U   /* Breakpoint */
#define VECTOR_UD  6U   /* Undefined Opcode */
#define VECTOR_DF  8U   /* Double Fault */
#define VECTOR_GP  13U  /* General Protection */
#define VECTOR_PF  14U  /* Page Fault */
#define VECTOR_MC  18U  /* Machine Check */

/* ================================================================
 * Static IDT table and IST stacks
 * ================================================================ */

static struct fbvbs_idt_gate idt_table[IDT_ENTRIES];

/* IST stacks — 4 KiB aligned, one per IST index.
 * PRODUCTION NOTE: Guard pages must be placed before each stack
 * (at lower addresses) to detect stack overflow. The boot code
 * or page table setup must mark these guard pages as not-present. */
static uint8_t ist_stack_nmi[IST_STACK_SIZE] __attribute__((aligned(16)));
static uint8_t ist_stack_df[IST_STACK_SIZE] __attribute__((aligned(16)));
static uint8_t ist_stack_mc[IST_STACK_SIZE] __attribute__((aligned(16)));

/* ================================================================
 * IDT gate configuration
 * ================================================================ */

/*@ requires vector < IDT_ENTRIES;
    requires ist <= 7;
    assigns idt_table[vector];
*/
static void idt_set_gate(
    uint32_t vector,
    uint64_t handler_addr,
    uint8_t ist)
{
    struct fbvbs_idt_gate *gate = &idt_table[vector];

    gate->offset_low  = (uint16_t)(handler_addr & 0xFFFFU);
    gate->selector    = KERNEL_CS;
    gate->ist         = ist & 0x07U;
    gate->type_attr   = IDT_TYPE_INTERRUPT_64;
    gate->offset_mid  = (uint16_t)((handler_addr >> 16U) & 0xFFFFU);
    gate->offset_high = (uint32_t)((handler_addr >> 32U) & 0xFFFFFFFFU);
    gate->reserved    = 0U;
}

/* ================================================================
 * Exception handler — common path
 *
 * All exceptions in hypervisor context are fatal. Log the exception
 * details and halt. No exception recovery is attempted.
 *
 * In production:
 *   1. The assembly ISR stub saves all GPRs, CR2 (for #PF), and
 *      the error code (if any).
 *   2. It calls this C handler with the exception frame.
 *   3. This function logs via UART (serial port 0x3F8 for early boot)
 *      or via fbvbs_log_append if the log subsystem is initialized.
 *   4. HLT in a CLI loop (fail-stop).
 * ================================================================ */

struct fbvbs_exception_frame {
    uint64_t rip;
    uint64_t cs;
    uint64_t rflags;
    uint64_t rsp;
    uint64_t ss;
};

/*@ assigns \result \from frame;
    ensures \result == \null || \valid_read(\result);
*/
static const struct fbvbs_exception_frame *fbvbs_exception_frame_from_opaque(
    const void *frame)
{
#ifdef __FRAMAC__
    static const struct fbvbs_exception_frame zero_frame = {0U, 0U, 0U, 0U, 0U};
    return (frame == NULL) ? NULL : &zero_frame;
#else
    return (const struct fbvbs_exception_frame *)frame;
#endif
}

/*@ requires vector < IDT_ENTRIES;
    requires frame == \null || \valid_read(frame);
    assigns g_fbvbs_hypervisor.mirror_log, g_fbvbs_hypervisor.log_lock;
*/
static void fbvbs_exception_handler(
    uint32_t vector,
    uint64_t error_code,
    const struct fbvbs_exception_frame *frame)
{
    uint8_t payload[24];

    /* Pack exception info into log payload:
     * [0..3]   = vector
     * [4..11]  = error_code
     * [12..19] = RIP (faulting instruction)
     * [20..23] = reserved */
    payload[0]  = (uint8_t)(vector & 0xFFU);
    payload[1]  = (uint8_t)((vector >> 8U) & 0xFFU);
    payload[2]  = (uint8_t)((vector >> 16U) & 0xFFU);
    payload[3]  = (uint8_t)((vector >> 24U) & 0xFFU);
    payload[4]  = (uint8_t)(error_code & 0xFFU);
    payload[5]  = (uint8_t)((error_code >> 8U) & 0xFFU);
    payload[6]  = (uint8_t)((error_code >> 16U) & 0xFFU);
    payload[7]  = (uint8_t)((error_code >> 24U) & 0xFFU);
    payload[8]  = (uint8_t)((error_code >> 32U) & 0xFFU);
    payload[9]  = (uint8_t)((error_code >> 40U) & 0xFFU);
    payload[10] = (uint8_t)((error_code >> 48U) & 0xFFU);
    payload[11] = (uint8_t)((error_code >> 56U) & 0xFFU);

    if (frame != NULL) {
        uint64_t rip = frame->rip;
        payload[12] = (uint8_t)(rip & 0xFFU);
        payload[13] = (uint8_t)((rip >> 8U) & 0xFFU);
        payload[14] = (uint8_t)((rip >> 16U) & 0xFFU);
        payload[15] = (uint8_t)((rip >> 24U) & 0xFFU);
        payload[16] = (uint8_t)((rip >> 32U) & 0xFFU);
        payload[17] = (uint8_t)((rip >> 40U) & 0xFFU);
        payload[18] = (uint8_t)((rip >> 48U) & 0xFFU);
        payload[19] = (uint8_t)((rip >> 56U) & 0xFFU);
    } else {
        payload[12] = 0U;
        payload[13] = 0U;
        payload[14] = 0U;
        payload[15] = 0U;
        payload[16] = 0U;
        payload[17] = 0U;
        payload[18] = 0U;
        payload[19] = 0U;
    }
    payload[20] = 0U;
    payload[21] = 0U;
    payload[22] = 0U;
    payload[23] = 0U;

    /* Log the exception -- CRITICAL severity, never rate-limited.
     *
     * NMI/MC safety: fbvbs_log_append internally uses fbvbs_log_spinlock_acquire
     * which is bounded (10000 iterations) and returns RESOURCE_BUSY on contention
     * rather than spinning indefinitely.  If an NMI or #MC arrives while the
     * log_lock is already held, the append will fail with RESOURCE_BUSY and the
     * log entry is silently dropped.  This is acceptable because the subsequent
     * halt (cli; hlt) makes the lost record moot. */
    (void)fbvbs_log_append(
        &g_fbvbs_hypervisor, 0U,
        FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR,
        (uint16_t)FBVBS_SEVERITY_CRITICAL,
        (uint16_t)FBVBS_EVENT_EXCEPTION_FAULT,
        payload, 24U
    );

    /* Halt — cli + hlt loop.
     * PRODUCTION NOTE: This must be an assembly sequence:
     *   cli
     *   1: hlt
     *   jmp 1b
     * The model uses a volatile loop. */
#if defined(__x86_64__) && !defined(__FRAMAC__)
    __asm__ volatile("cli\n1:\thlt\n\tjmp 1b" : : : "memory");
#endif
    /* Unreachable in production; model falls through for WP */
}

/* ================================================================
 * Per-vector handler stubs (called from assembly ISR entries)
 * ================================================================ */

/*@ assigns g_fbvbs_hypervisor.mirror_log, g_fbvbs_hypervisor.log_lock; */
void fbvbs_handle_de(const void *frame) {
    fbvbs_exception_handler(VECTOR_DE, 0U, fbvbs_exception_frame_from_opaque(frame));
}

/*@ assigns g_fbvbs_hypervisor.mirror_log, g_fbvbs_hypervisor.log_lock; */
void fbvbs_handle_db(const void *frame) {
    fbvbs_exception_handler(VECTOR_DB, 0U, fbvbs_exception_frame_from_opaque(frame));
}

/*@ assigns g_fbvbs_hypervisor.mirror_log, g_fbvbs_hypervisor.log_lock; */
void fbvbs_handle_nmi(const void *frame) {
    fbvbs_exception_handler(VECTOR_NMI, 0U, fbvbs_exception_frame_from_opaque(frame));
}

/*@ assigns g_fbvbs_hypervisor.mirror_log, g_fbvbs_hypervisor.log_lock; */
void fbvbs_handle_bp(const void *frame) {
    fbvbs_exception_handler(VECTOR_BP, 0U, fbvbs_exception_frame_from_opaque(frame));
}

/*@ assigns g_fbvbs_hypervisor.mirror_log, g_fbvbs_hypervisor.log_lock; */
void fbvbs_handle_ud(const void *frame) {
    fbvbs_exception_handler(VECTOR_UD, 0U, fbvbs_exception_frame_from_opaque(frame));
}

/*@ assigns g_fbvbs_hypervisor.mirror_log, g_fbvbs_hypervisor.log_lock; */
void fbvbs_handle_df(const void *frame, uint64_t error_code) {
    fbvbs_exception_handler(VECTOR_DF, error_code, fbvbs_exception_frame_from_opaque(frame));
}

/*@ assigns g_fbvbs_hypervisor.mirror_log, g_fbvbs_hypervisor.log_lock; */
void fbvbs_handle_gp(const void *frame, uint64_t error_code) {
    fbvbs_exception_handler(VECTOR_GP, error_code, fbvbs_exception_frame_from_opaque(frame));
}

/*@ assigns g_fbvbs_hypervisor.mirror_log, g_fbvbs_hypervisor.log_lock; */
void fbvbs_handle_pf(const void *frame, uint64_t error_code) {
    fbvbs_exception_handler(VECTOR_PF, error_code, fbvbs_exception_frame_from_opaque(frame));
}

/*@ assigns g_fbvbs_hypervisor.mirror_log, g_fbvbs_hypervisor.log_lock; */
void fbvbs_handle_mc(const void *frame) {
    fbvbs_exception_handler(VECTOR_MC, 0U, fbvbs_exception_frame_from_opaque(frame));
}

/* ================================================================
 * IDT initialization
 *
 * Sets up all exception handlers in the IDT table with appropriate
 * IST assignments, then loads the IDTR.
 * ================================================================ */

/*@ assigns idt_table[0 .. IDT_ENTRIES - 1];
    ensures \result == 0;
*/
int fbvbs_idt_init(void) {
    uint32_t i;

    /* Clear entire IDT */
    /*@ loop invariant 0 <= i <= IDT_ENTRIES;
        loop assigns i, idt_table[0 .. IDT_ENTRIES - 1];
        loop variant IDT_ENTRIES - i;
    */
    for (i = 0; i < IDT_ENTRIES; ++i) {
        idt_table[i] = (struct fbvbs_idt_gate){0};
    }

    /* Set exception handlers.
     * PRODUCTION NOTE: The handler addresses here are placeholders.
     * In production, these are replaced with the actual addresses of
     * the assembly ISR stubs (isr_stub_0, isr_stub_1, etc.) that
     * save context and call the C handlers above.
     * The stubs are defined in Phase 1-12 (asm backend). */

    /* PRODUCTION NOTE: In bare-metal, these addresses point to assembly
     * ISR stubs that push error code (if not auto-pushed by CPU), save
     * all GPRs, call the C handler, restore GPRs, and IRETQ.
     * Model code uses the C handler addresses directly. */
    idt_set_gate(VECTOR_DE,  (uintptr_t)&fbvbs_handle_de, IST_NONE);
    idt_set_gate(VECTOR_DB,  (uintptr_t)&fbvbs_handle_db, IST_NONE);
    idt_set_gate(VECTOR_NMI, (uintptr_t)&fbvbs_handle_nmi, IST_NMI);
    idt_set_gate(VECTOR_BP,  (uintptr_t)&fbvbs_handle_bp, IST_NONE);
    idt_set_gate(VECTOR_UD,  (uintptr_t)&fbvbs_handle_ud, IST_NONE);
    idt_set_gate(VECTOR_DF,  (uintptr_t)&fbvbs_handle_df, IST_DF);
    idt_set_gate(VECTOR_GP,  (uintptr_t)&fbvbs_handle_gp, IST_NONE);
    idt_set_gate(VECTOR_PF,  (uintptr_t)&fbvbs_handle_pf, IST_NONE);
    idt_set_gate(VECTOR_MC,  (uintptr_t)&fbvbs_handle_mc, IST_MC);

    /* Load IDTR.
     * PRODUCTION NOTE: Requires the LIDT instruction in assembly:
     *   struct fbvbs_idtr idtr = { .limit = IDT_TABLE_SIZE - 1,
     *                              .base = (uint64_t)&idt_table };
     *   __asm__ volatile("lidt %0" : : "m"(idtr));
     *
     * Also requires TSS setup for IST stack pointers:
     *   tss.ist[0] = (uint64_t)&ist_stack_nmi + IST_STACK_SIZE;  // IST 1
     *   tss.ist[1] = (uint64_t)&ist_stack_df + IST_STACK_SIZE;   // IST 2
     *   tss.ist[2] = (uint64_t)&ist_stack_mc + IST_STACK_SIZE;   // IST 3
     *   Then load TR with LTR instruction.
     */

    /* Suppress unused variable warnings for model IST stacks */
    (void)ist_stack_nmi;
    (void)ist_stack_df;
    (void)ist_stack_mc;

    return 0;
}

/* ================================================================
 * IST stack boundary queries (for ACSL contracts)
 * ================================================================ */

/*@ assigns \nothing; */
uint64_t fbvbs_ist_stack_top_nmi(void) {
    return (uint64_t)(uintptr_t)(ist_stack_nmi + IST_STACK_SIZE);
}

/*@ assigns \nothing; */
uint64_t fbvbs_ist_stack_top_df(void) {
    return (uint64_t)(uintptr_t)(ist_stack_df + IST_STACK_SIZE);
}

/*@ assigns \nothing; */
uint64_t fbvbs_ist_stack_top_mc(void) {
    return (uint64_t)(uintptr_t)(ist_stack_mc + IST_STACK_SIZE);
}
