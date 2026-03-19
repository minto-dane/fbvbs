/*
 * FBVBS Hypervisor Linker Script
 *
 * Enforces W^X at the page level:
 *   .text            — RX  (executable, not writable)
 *   .rodata          — R   (read-only, not executable)
 *   .data / .bss     — RW  (writable, not executable)
 *
 * Section boundaries are page-aligned so boot.S can set per-page
 * NX and R/W bits in the identity-map page tables.
 *
 * Symbols exported for boot.S:
 *   _binary_start, _binary_end   — full image extent
 *   _text_start,   _text_end     — code
 *   _rodata_start, _rodata_end   — read-only data
 *   _data_start                  — mutable data start
 *   _bss_end                     — end of BSS (and image)
 */

ENTRY(_start)
OUTPUT_FORMAT(elf64-x86-64)

SECTIONS
{
    /* Standard Multiboot2 load address */
    . = 1M;

    _binary_start = .;

    /* Multiboot2 header must be within the first 32 KiB of the image.
     * Placed before .text in its own read-only region. */
    .multiboot_header : ALIGN(8)
    {
        *(.multiboot_header)
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

    /* ---- Read-only data (R, NX=1, W=0) ---- */
    _rodata_start = .;
    .rodata :
    {
        *(.rodata)
        *(.rodata.*)
    }
    . = ALIGN(4096);
    _rodata_end = .;

    /* ---- Read-write initialised data (RW, NX=1) ---- */
    _data_start = .;
    .data :
    {
        *(.data)
        *(.data.*)
    }
    . = ALIGN(4096);

    /* ---- BSS: zero-initialised (RW, NX=1) ---- */
    _bss_start = .;
    .bss :
    {
        *(.bss)
        *(.bss.*)
        *(COMMON)
    }
    . = ALIGN(4096);
    _bss_end = .;

    _binary_end = .;

    /* Discard unneeded sections */
    /DISCARD/ :
    {
        *(.comment)
        *(.eh_frame)
        *(.eh_frame_hdr)
    }
}
