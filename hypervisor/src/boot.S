/* FBVBS Hypervisor Boot Entry Point
 *
 * Security features:
 * - W^X enforcement via per-page NX and R/W bits:
 *     .text          → RX   (executable, not writable)
 *     .rodata        → R+NX (read-only, not executable)
 *     .data/.bss     → RW+NX (read-write, not executable)
 *     stack          → RW+NX (read-write, not executable)
 * - Stack guard page: unmapped 4 KiB page below the stack
 * - EFER.NXE enabled when CPU supports NX bit
 * - CR0.WP enabled so ring-0 respects R/W page table bits
 * - Page table overflow protection (max 2048 pages = 8 MiB)
 * - Multiboot2 info mapped at its actual physical address
 *
 * Page table layout (identity map, 4 KiB pages):
 *   PML4[0] → PDPT[0] → PD[0..3] → pt_pool[0..3]
 *   Each PT covers 2 MiB (512 × 4 KiB), total 8 MiB coverage
 *
 * Section boundaries (_text_start, _text_end, etc.) are defined
 * by the linker script (fbvbs.ld).
 */

/* ================================================================
 * Multiboot2 Header
 * ================================================================ */
.section .multiboot_header, "a"
.align 8

multiboot_header:
    .long 0xE85250D6                /* magic number */
    .long 0                         /* architecture (i386) */
    .long multiboot_header_end - multiboot_header  /* header length */
    .long -(0xE85250D6 + 0 + (multiboot_header_end - multiboot_header))  /* checksum */

    /* Information request: memory map */
    .word 1, 0
    .long 12
    .long 6
    .long 0                         /* padding to 8-byte alignment */

    /* Information request: basic memory info */
    .word 1, 0
    .long 12
    .long 4
    .long 0

    /* Information request: boot device */
    .word 1, 0
    .long 12
    .long 5
    .long 0

    /* Information request: command line */
    .word 1, 0
    .long 12
    .long 1
    .long 0

    /* Information request: module info */
    .word 1, 0
    .long 12
    .long 3
    .long 0

    /* Information request: framebuffer */
    .word 1, 0
    .long 12
    .long 8
    .long 0

    /* End tag */
    .word 0, 0
    .long 8
multiboot_header_end:

/* ================================================================
 * 32-bit Entry Point
 * ================================================================ */
.section .text
.code32
.global _start
.type _start, @function

_start:
    /* Disable interrupts immediately */
    cli

    /* Save Multiboot information pointer */
    mov %ebx, %edi
    mov %ebx, (saved_multiboot_ptr)

    /* Set up minimal 32-bit stack (16-byte aligned for ABI) */
    mov $stack_top, %esp
    and $-16, %esp

    /* Verify long mode support */
    call check_long_mode
    test %eax, %eax
    jz .Lno_long_mode_error

    /* Check NX bit support (CPUID.80000001H:EDX.NX, bit 20) */
    call check_nx_support
    mov %eax, (nx_supported)

    /* Build W^X page tables using linker section symbols */
    call setup_page_tables_wx

    /* Enable PAE (required for long mode) */
    mov %cr4, %eax
    or $0x20, %eax                  /* CR4.PAE */
    mov %eax, %cr4

    /* Load page table root */
    mov $pml4, %eax
    mov %eax, %cr3

    /* Enable long mode in EFER, plus NXE if supported */
    mov $0xC0000080, %ecx           /* IA32_EFER MSR */
    rdmsr
    or $0x100, %eax                 /* EFER.LME */
    cmpl $0, (nx_supported)
    jz .Lskip_nxe
    or $0x800, %eax                 /* EFER.NXE */
.Lskip_nxe:
    wrmsr

    /* Enable paging with write-protect enforcement */
    mov %cr0, %eax
    or $0x80010001, %eax            /* CR0.PG | CR0.WP | CR0.PE */
    mov %eax, %cr0

    /* Load 64-bit GDT and jump to long mode */
    lgdt gdt64_pointer
    ljmp $0x08, $start64

.Lno_long_mode_error:
    mov $error_no_long_mode, %esi
    call print_string_32
    jmp .Lhalt_forever

/* ================================================================
 * 64-bit Entry
 * ================================================================ */
.code64
start64:
    /* Set up 64-bit segment registers (flat model) */
    xor %rax, %rax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %gs
    mov %ax, %ss

    /* Set up 64-bit stack with proper alignment */
    mov $stack_top, %rsp
    and $-16, %rsp

    /* Clear base pointer for clean backtraces */
    xor %rbp, %rbp

    /* Zero-extend EDI→RDI (Multiboot info pointer) */
    mov %edi, %edi
    call fbvbs_kernel_main

    /* Should never return */
.Lhalt:
    cli
    hlt
    jmp .Lhalt

.Lhalt_forever:
    cli
    hlt
    jmp .Lhalt_forever

/* ================================================================
 * Print string in 32-bit protected mode (error path only)
 * ESI = pointer to NUL-terminated ASCII string
 * ================================================================ */
print_string_32:
    push %ebx
    push %esi
    push %edi                       /* Save EDI (callee-saved) */
    mov $0xB8000, %edi              /* VGA text buffer */
    mov $0x0F, %ah                  /* White on black */
.Lprint_loop:
    lodsb
    test %al, %al
    jz .Lprint_done
    stosw
    jmp .Lprint_loop
.Lprint_done:
    pop %edi
    pop %esi
    pop %ebx
    ret

/* ================================================================
 * Check if CPU supports long mode
 * Returns: EAX = 1 if supported, 0 otherwise
 * ================================================================ */
check_long_mode:
    push %ebx

    /* Test CPUID support by toggling EFLAGS.ID (bit 21) */
    pushf
    pop %eax
    mov %eax, %ecx
    xor $0x200000, %eax
    push %eax
    popf
    pushf
    pop %eax
    xor %ecx, %eax
    shr $21, %eax
    and $1, %eax
    jz .Lno_cpuid

    /* Check extended CPUID availability */
    mov $0x80000000, %eax
    cpuid
    cmp $0x80000001, %eax
    jb .Lno_long_mode_check

    /* Check long mode bit */
    mov $0x80000001, %eax
    cpuid
    and $0x20000000, %edx           /* CPUID.80000001H:EDX.LM (bit 29) */
    shr $29, %edx
    mov %edx, %eax
    jmp .Lcheck_done

.Lno_cpuid:
.Lno_long_mode_check:
    xor %eax, %eax

.Lcheck_done:
    pop %ebx
    ret

/* ================================================================
 * Check if CPU supports the NX bit
 * Returns: EAX = 1 if supported, 0 otherwise
 * Precondition: extended CPUID leaf 0x80000001 is available
 *               (guaranteed by prior check_long_mode success)
 * ================================================================ */
check_nx_support:
    push %ebx
    mov $0x80000001, %eax
    cpuid
    test $(1 << 20), %edx           /* CPUID.80000001H:EDX.NX (bit 20) */
    jz .Lno_nx
    mov $1, %eax
    pop %ebx
    ret
.Lno_nx:
    xor %eax, %eax
    pop %ebx
    ret

/* ================================================================
 * Set up identity-mapped page tables with W^X enforcement
 *
 * Uses linker symbols for section boundaries:
 *   _binary_start .. _text_start  → R+NX   (multiboot header)
 *   _text_start   .. _text_end    → RX      (code)
 *   _rodata_start .. _rodata_end  → R+NX    (read-only data)
 *   _data_start   .. _bss_end     → RW+NX   (data + BSS)
 *   stack_bottom  .. stack_top    → RW+NX   (stack)
 *   stack_guard                   → unmapped (guard page)
 *   Multiboot info (2 pages)      → RW+NX   (at actual phys addr)
 *
 * PTE format (64-bit):
 *   Low  dword: phys_addr[31:12] | flags[11:0]
 *   High dword: phys_addr[63:32] | NX (bit 31)
 *
 * Page table overflow protection: max 2048 pages (8 MiB)
 * ================================================================ */
setup_page_tables_wx:
    push %ebx
    push %esi
    push %edi
    push %ebp

    /* ---- Clear all page table memory ---- */
    /* pml4 + pdpt + pd + pt_pool = 3×4096 + 4×4096 = 28672 bytes */
    mov $pml4, %edi
    xor %eax, %eax
    mov $7168, %ecx                 /* 28672 / 4 = 7168 dwords */
    rep stosl

    /* ---- Wire up the hierarchy ---- */

    /* PML4[0] → PDPT  (Present + Write, NX=0) */
    mov $pdpt, %eax
    or $0x3, %eax
    mov %eax, (pml4)
    movl $0, (pml4 + 4)

    /* PDPT[0] → PD  (Present + Write, NX=0) */
    mov $pd, %eax
    or $0x3, %eax
    mov %eax, (pdpt)
    movl $0, (pdpt + 4)

    /* PD[0..3] → pt_pool[0..3]  (Present + Write, NX=0) */
    mov $0, %ebp                    /* PD entry index */
.Lpd_setup:
    cmp $4, %ebp
    jge .Lpd_done
    mov %ebp, %eax
    shl $12, %eax                   /* PT offset = index × 4096 */
    add $pt_pool, %eax              /* PT physical address */
    or $0x3, %eax                   /* Present + Write */
    mov %ebp, %esi
    shl $3, %esi                    /* PD byte offset = index × 8 */
    mov %eax, pd(%esi)              /* PD entry low dword */
    movl $0, pd+4(%esi)             /* PD entry high dword (NX=0) */
    inc %ebp
    jmp .Lpd_setup
.Lpd_done:

    /* ---- Determine NX flag for high dword ---- */
    cmpl $0, (nx_supported)
    jz .Lnx_zero
    movl $0x80000000, (nx_high_bits) /* Bit 31 of high dword = NX */
    jmp .Lnx_resolved
.Lnx_zero:
    movl $0, (nx_high_bits)
.Lnx_resolved:

    /* ---- Map sections with correct permissions ---- */

    /* Multiboot header region: R + NX (read-only, not executable) */
    mov $_binary_start, %eax
    mov $_text_start, %ebx
    mov $0x1, %ecx                  /* Present (no Write) */
    mov (nx_high_bits), %edx        /* NX */
    call map_page_range

    /* .text: RX (executable, not writable) */
    mov $_text_start, %eax
    mov $_text_end, %ebx
    mov $0x1, %ecx                  /* Present (no Write, no NX) */
    xor %edx, %edx                  /* NX = 0 → executable */
    call map_page_range

    /* .rodata: R + NX (read-only, not executable) */
    mov $_rodata_start, %eax
    mov $_rodata_end, %ebx
    mov $0x1, %ecx                  /* Present (no Write) */
    mov (nx_high_bits), %edx        /* NX */
    call map_page_range

    /* .data + .bss: RW + NX (read-write, not executable) */
    mov $_data_start, %eax
    mov $_bss_end, %ebx
    mov $0x3, %ecx                  /* Present + Write */
    mov (nx_high_bits), %edx        /* NX */
    call map_page_range

    /* Stack: RW + NX */
    mov $stack_bottom, %eax
    mov $stack_top, %ebx
    mov $0x3, %ecx                  /* Present + Write */
    mov (nx_high_bits), %edx        /* NX */
    call map_page_range

    /* Unmap the guard page (clear its PTE → page fault on overflow) */
    mov $stack_guard, %eax
    call unmap_page

    /* Map Multiboot info at its real physical address (RW + NX, 4 pages) */
    mov (saved_multiboot_ptr), %eax
    and $0xFFFFF000, %eax           /* Page-align down */
    test %eax, %eax
    jz .Lskip_mboot_map
    mov %eax, %ebx
    add $0x4000, %ebx               /* 4 pages (16 KiB) for info struct */
    mov $0x3, %ecx                  /* Present + Write */
    mov (nx_high_bits), %edx        /* NX */
    call map_page_range
.Lskip_mboot_map:

    pop %ebp
    pop %edi
    pop %esi
    pop %ebx
    ret

/* ================================================================
 * map_page_range: Map 4 KiB pages in the identity-mapped PT pool
 *
 * Input:
 *   EAX = start physical address (page-aligned)
 *   EBX = end physical address (page-aligned, exclusive)
 *   ECX = PTE flags for low dword (bits 0-11)
 *   EDX = PTE flags for high dword (bit 31 = NX)
 *
 * Clobbers: EAX, ESI
 * Preserves: EBX, ECX, EDX, EDI, EBP
 *
 * Overflow protection: stops if page index >= 2048 (beyond pt_pool)
 * ================================================================ */
map_page_range:
.Lmap_range_loop:
    cmp %ebx, %eax
    jae .Lmap_range_done
    /* Compute flat PTE address: pt_pool + (phys >> 12) × 8 */
    mov %eax, %esi
    shr $12, %esi
    cmp $2048, %esi                 /* 4 PTs × 512 entries */
    jae .Lmap_range_done
    shl $3, %esi
    add $pt_pool, %esi
    /* Write PTE low dword: phys_addr | flags (bits 0-11 of phys are 0) */
    push %eax
    or %ecx, %eax
    mov %eax, (%esi)
    pop %eax
    /* Write PTE high dword: NX flag (phys < 4 GiB so upper addr bits = 0) */
    mov %edx, 4(%esi)
    /* Advance to next 4 KiB page */
    add $0x1000, %eax
    jmp .Lmap_range_loop
.Lmap_range_done:
    ret

/* ================================================================
 * unmap_page: Clear PTE for a single page (creates a guard hole)
 *
 * Input: EAX = physical address (page-aligned)
 * Clobbers: ESI
 * ================================================================ */
unmap_page:
    mov %eax, %esi
    shr $12, %esi
    cmp $2048, %esi
    jae .Lunmap_done
    shl $3, %esi
    add $pt_pool, %esi
    movl $0, (%esi)
    movl $0, 4(%esi)
.Lunmap_done:
    ret

/* ================================================================
 * Read-only data
 * ================================================================ */
.section .rodata

error_no_long_mode:
    .asciz "ERROR: CPU does not support 64-bit long mode"

.align 8
gdt64:
    .quad 0x0000000000000000        /* Null descriptor */
    .quad 0x00AF9A000000FFFF        /* 64-bit code: DPL=0, Execute/Read */
    .quad 0x00AF92000000FFFF        /* 64-bit data: DPL=0, Read/Write */
gdt64_end:

gdt64_pointer:
    .word gdt64_end - gdt64 - 1
    .quad gdt64

/* ================================================================
 * BSS — page-aligned structures
 * ================================================================ */
.section .bss

/* Small boot-time variables */
.align 4
saved_multiboot_ptr:
    .space 4
nx_supported:
    .space 4
nx_high_bits:
    .space 4

/* Page tables: PML4, PDPT, PD, and 4 PT tables (8 MiB coverage) */
.align 4096
pml4:
    .space 4096
pdpt:
    .space 4096
pd:
    .space 4096
pt_pool:
    .space 16384                    /* 4 × 4096 = 4 PTs, 2048 pages */

/* Stack with guard page */
.align 4096
stack_guard:
    .space 4096                     /* NOT mapped → page fault on overflow */
stack_bottom:
    .space 16384                    /* 16 KiB stack */
stack_top:

/* Mark stack as non-executable */
.section .note.GNU-stack,"",@progbits
