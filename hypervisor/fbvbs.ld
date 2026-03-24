/*
 * FBVBS Hypervisor Linker Script
 *
 * Phase 1-11: Guard pages + segment separation for defense-in-depth.
 *
 * Security properties:
 *   - W^X enforcement: .text=RX, .rodata=R, .data/.bss=RW (NX via boot.S)
 *   - Guard pages (4 KiB unmapped gaps) between each section to detect
 *     buffer overflows and underflows at section boundaries
 *   - IST stacks in dedicated section with per-stack guard pages
 *   - Stack guard page below the boot stack
 *   - BSS zeroed by boot.S before C entry
 *   - All sections page-aligned for per-page permission control
 *
 * Symbols exported for boot.S:
 *   _binary_start, _binary_end         -- full image extent
 *   _text_start, _text_end             -- code (RX)
 *   _rodata_start, _rodata_end         -- read-only data (R)
 *   _data_start, _data_end             -- initialized data (RW)
 *   _bss_start, _bss_end              -- zero-init data (RW)
 *   _guard_*                           -- guard page addresses (unmapped)
 *   _ist[1-3]_stack_top                -- IST stack tops for IDT
 *   _stack_guard, _stack_bottom, _stack_top -- boot stack layout
 *
 * Reference: Intel SDM Vol. 3, Chapter 4 (Paging)
 */

ENTRY(_start)
OUTPUT_FORMAT(elf64-x86-64)

GUARD_PAGE_SIZE = 4096;

SECTIONS
{
    /* Standard Multiboot2 load address */
    . = 1M;

    _binary_start = .;

    /* Multiboot2 header must be within the first 32 KiB of the image.
     * Placed before .text in its own read-only region. */
    .multiboot_header : ALIGN(8)
    {
        KEEP(*(.multiboot_header))
    }

    /* ---- Executable code (RX, NX=0, W=0) ---- */
    . = ALIGN(4096);
    _text_start = .;
    .text :
    {
        *(.text)
        *(.text.*)
    }
    . = ALIGN(4096);
    _text_end = .;

    /* Guard page: .text / .rodata boundary */
    _guard_text_rodata = .;
    . += GUARD_PAGE_SIZE;

    /* ---- Read-only data (R, NX=1, W=0) ---- */
    . = ALIGN(4096);
    _rodata_start = .;
    .rodata :
    {
        *(.rodata)
        *(.rodata.*)
    }
    . = ALIGN(4096);
    _rodata_end = .;

    /* Guard page: .rodata / .data boundary */
    _guard_rodata_data = .;
    . += GUARD_PAGE_SIZE;

    /* ---- Read-write initialised data (RW, NX=1) ---- */
    . = ALIGN(4096);
    _data_start = .;
    .data :
    {
        *(.data)
        *(.data.*)
    }
    . = ALIGN(4096);
    _data_end = .;

    /* Guard page: .data / .bss boundary */
    _guard_data_bss = .;
    . += GUARD_PAGE_SIZE;

    /* ---- BSS: zero-initialised (RW, NX=1) ---- */
    . = ALIGN(4096);
    _bss_start = .;
    .bss (NOLOAD) :
    {
        *(.bss)
        *(.bss.*)
        *(COMMON)
    }
    . = ALIGN(4096);
    _bss_end = .;

    /* Guard page: .bss / IST stacks boundary */
    _guard_bss_ist = .;
    . += GUARD_PAGE_SIZE;

    /* ---- IST (Interrupt Stack Table) stacks (RW, NX=1) ----
     *
     * Dedicated stacks for fault handlers that cannot use the
     * normal kernel stack (it might be corrupted):
     *   IST1: #NMI handler (4 KiB)
     *   IST2: #DF  handler (4 KiB)
     *   IST3: #MC  handler (4 KiB)
     *
     * Each stack has a guard page below it (unmapped) to detect
     * stack overflow during fault handling. Stacks grow downward;
     * _istN_stack_top is the initial RSP value for the IDT entry.
     */
    . = ALIGN(4096);
    _ist_stacks_start = .;

    /* IST1 (NMI) */
    _ist1_guard = .;
    . += GUARD_PAGE_SIZE;
    _ist1_stack_bottom = .;
    . += 4096;
    _ist1_stack_top = .;

    /* IST2 (Double Fault) */
    _ist2_guard = .;
    . += GUARD_PAGE_SIZE;
    _ist2_stack_bottom = .;
    . += 4096;
    _ist2_stack_top = .;

    /* IST3 (Machine Check) */
    _ist3_guard = .;
    . += GUARD_PAGE_SIZE;
    _ist3_stack_bottom = .;
    . += 4096;
    _ist3_stack_top = .;

    _ist_stacks_end = .;

    /* Guard page: IST stacks / boot stack boundary */
    _guard_ist_stack = .;
    . += GUARD_PAGE_SIZE;

    /* ---- Boot/hypervisor stack (RW, NX=1) ----
     * 16 KiB stack with guard page below. */
    . = ALIGN(4096);
    _stack_guard = .;
    . += GUARD_PAGE_SIZE;
    _stack_bottom = .;
    . += 16384;
    _stack_top = .;

    . = ALIGN(4096);
    _binary_end = .;

    /* Discard unneeded sections */
    /DISCARD/ :
    {
        *(.comment)
        *(.note .note.*)
        *(.eh_frame)
        *(.eh_frame_hdr)
        *(.gnu.hash)
        *(.dynsym)
        *(.dynstr)
        *(.dynamic)
        *(.rela .rela.*)
    }
}

/* ---- Layout assertions ---- */
ASSERT(_binary_end - _binary_start <= 16M,
       "Hypervisor image exceeds 16 MiB early-identity-map budget")
ASSERT(_text_start % 4096 == 0, ".text must be page-aligned")
ASSERT(_rodata_start % 4096 == 0, ".rodata must be page-aligned")
ASSERT(_data_start % 4096 == 0, ".data must be page-aligned")
ASSERT(_bss_start % 4096 == 0, ".bss must be page-aligned")
ASSERT(_stack_bottom % 4096 == 0, "Stack must be page-aligned")
ASSERT(_ist1_stack_top % 4096 == 0, "IST1 stack must be page-aligned")
ASSERT(_ist2_stack_top % 4096 == 0, "IST2 stack must be page-aligned")
ASSERT(_ist3_stack_top % 4096 == 0, "IST3 stack must be page-aligned")
