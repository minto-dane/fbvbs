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
 * - Page table overflow protection (max 1048576 pages ~= 4 GiB)
 * - Multiboot2 info mapped at its actual physical address
 *
 * Page table layout (identity map, 4 KiB pages):
 *   PML4[0] → PDPT[0..3] → pd_pool[0..3] → pt_pool[0..2047]
 *   Each PT covers 2 MiB (512 × 4 KiB), total just under 4 GiB coverage.
 *   The broader early mapping allows ACPI/XSDT/DMAR tables and other
 *   firmware structures to be reached during early retained-C init.
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

    /* Information request: ACPI RSDP (old) */
    .word 1, 0
    .long 12
    .long 14
    .long 0

    /* Information request: ACPI RSDP (new) */
    .word 1, 0
    .long 12
    .long 15
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
    cld

    /* Take ownership of segmentation state immediately instead of relying
     * on bootloader-provided hidden descriptor caches. */
    lgdt boot_gdt_pointer_32
    /* Emit an explicit ptr16:32 far jump so the mode-transition encoding
     * does not depend on GAS heuristics inside an ELF64 object. */
    .byte 0xEA
    .long .Lboot32_entry
    .word 0x08

.Lboot32_entry:
    mov $0x10, %ax
    mov %ax, %es
    mov %ax, %ss
    mov %ax, %ds
    mov %ax, %fs
    mov %ax, %gs

    /* Save Multiboot information pointer */
    mov %ebx, %edi
    mov %ebx, (saved_multiboot_ptr)

    /* Set up minimal 32-bit stack (16-byte aligned for ABI) */
    mov $stack_top, %esp
    and $-16, %esp

    /* Bring up COM1 early so QEMU/serial smoke tests can see where
     * the boot path stalls even before the retained-C runtime is live. */
    call serial_init_32
    mov $boot_msg_32, %esi
    call serial_print_32

    /* Verify long mode support */
    call check_long_mode
    test %eax, %eax
    jz .Lno_long_mode_error
    mov $boot_msg_lm_ok, %esi
    call serial_print_32

    /* Check NX bit support (CPUID.80000001H:EDX.NX, bit 20) */
    call check_nx_support
    mov %eax, (nx_supported)

    /* Build W^X page tables using linker section symbols */
    call setup_page_tables_wx
    mov $boot_msg_pt_ready, %esi
    call serial_print_32

    /* Enable PAE (required for long mode) */
    mov %cr4, %eax
    or $0x20, %eax                  /* CR4.PAE */
    mov %eax, %cr4
    mov $boot_msg_cr4_ready, %esi
    call serial_print_32

    /* Load page table root */
    mov $pml4, %eax
    mov %eax, %cr3
    mov $boot_msg_cr3_ready, %esi
    call serial_print_32

    /* Enable long mode in EFER, plus NXE if supported */
    mov $0xC0000080, %ecx           /* IA32_EFER MSR */
    rdmsr
    or $0x100, %eax                 /* EFER.LME */
    cmpl $0, (nx_supported)
    jz .Lskip_nxe
    or $0x800, %eax                 /* EFER.NXE */
.Lskip_nxe:
    wrmsr
    mov $boot_msg_efer_ready, %esi
    call serial_print_32

    /* Load the long-mode GDT before enabling paging so that the only
     * instruction after CR0.PG is the mandatory far jump into the
     * 64-bit code segment. */
    lgdt boot_gdt_pointer_32
    mov $boot_msg_enter_64, %esi
    call serial_print_32

    /* Enable paging with write-protect enforcement */
    mov %cr0, %eax
    or $0x80010001, %eax            /* CR0.PG | CR0.WP | CR0.PE */
    mov %eax, %cr0
    .byte 0xEA
    .long start64
    .word 0x18

.Lno_long_mode_error:
    mov $boot_msg_no_lm, %esi
    call serial_print_32
    mov $error_no_long_mode, %esi
    call print_string_32
    jmp .Lhalt_forever

/* ================================================================
 * 64-bit Entry
 * ================================================================ */
.code64
.p2align 4
start64:
    /* Set up 64-bit segment registers (flat model) */
    mov $0x10, %ax
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

    /* Raw 64-bit serial marker before the retained-C runtime is touched.
     * This lets QEMU/KVM smoke distinguish long-mode entry failures from
     * later runtime-init stalls. */
    lea boot_msg_64_entry(%rip), %rsi
    call serial_print_64

    /* Initialize bare-metal runtime services before the first C function:
     *   - seed stack protector guard
     *   - initialize COM1 boot console for QEMU/serial smoke tests */
    call fbvbs_boot_runtime_init
    lea boot_msg_64(%rip), %rdi
    call fbvbs_boot_console_puts

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
.code32
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
 * Early serial console in 32-bit mode
 * ================================================================ */
serial_init_32:
    mov $0x3F9, %dx                 /* Interrupt Enable Register */
    xor %al, %al
    out %al, %dx
    mov $0x3FB, %dx                 /* Line Control Register */
    mov $0x80, %al                  /* DLAB */
    out %al, %dx
    mov $0x3F8, %dx                 /* Divisor low = 1 */
    mov $0x01, %al
    out %al, %dx
    mov $0x3F9, %dx                 /* Divisor high = 0 */
    xor %al, %al
    out %al, %dx
    mov $0x3FB, %dx                 /* 8N1 */
    mov $0x03, %al
    out %al, %dx
    mov $0x3FA, %dx                 /* FIFO Control Register */
    mov $0xC7, %al
    out %al, %dx
    mov $0x3FC, %dx                 /* Modem Control Register */
    mov $0x0B, %al
    out %al, %dx
    ret

serial_putchar_32:
    push %ebx
    push %ecx
    push %edx
    mov %al, %bl
    mov $1000000, %ecx
.Lserial_wait:
    mov $0x3FD, %dx                 /* Line Status Register */
    in %dx, %al
    test $0x20, %al
    jnz .Lserial_ready
    dec %ecx
    jnz .Lserial_wait
    pop %edx
    pop %ecx
    pop %ebx
    ret
.Lserial_ready:
    mov $0x3F8, %dx
    mov %bl, %al
    out %al, %dx
    pop %edx
    pop %ecx
    pop %ebx
    ret

serial_print_32:
    push %eax
    push %esi
.Lserial_print_loop:
    lodsb
    test %al, %al
    jz .Lserial_print_done
    cmp $'\n', %al
    jne .Lserial_emit
    push %eax
    mov $'\r', %al
    call serial_putchar_32
    pop %eax
.Lserial_emit:
    call serial_putchar_32
    jmp .Lserial_print_loop
.Lserial_print_done:
    pop %esi
    pop %eax
    ret

/* ================================================================
 * Early serial console in 64-bit mode
 * ================================================================ */
.code64
serial_putchar_64:
    push %rbx
    push %rcx
    push %rdx
    mov %al, %bl
    mov $1000000, %ecx
.Lserial_wait_64:
    mov $0x3FD, %dx                 /* Line Status Register */
    in %dx, %al
    test $0x20, %al
    jnz .Lserial_ready_64
    dec %ecx
    jnz .Lserial_wait_64
    pop %rdx
    pop %rcx
    pop %rbx
    ret
.Lserial_ready_64:
    mov $0x3F8, %dx
    mov %bl, %al
    out %al, %dx
    pop %rdx
    pop %rcx
    pop %rbx
    ret

serial_print_64:
    push %rax
    push %rsi
.Lserial_print_loop_64:
    lodsb
    test %al, %al
    jz .Lserial_print_done_64
    cmp $'\n', %al
    jne .Lserial_emit_64
    push %rax
    mov $'\r', %al
    call serial_putchar_64
    pop %rax
.Lserial_emit_64:
    call serial_putchar_64
    jmp .Lserial_print_loop_64
.Lserial_print_done_64:
    pop %rsi
    pop %rax
    ret

/* ================================================================
 * Check if CPU supports long mode
 * Returns: EAX = 1 if supported, 0 otherwise
 * ================================================================ */
.code32
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
 *
 * Multiboot metadata is reached through the broad near-4 GiB identity map.
 * We intentionally do not apply a second blanket remap for the Multiboot
 * pointer range, because some bootloaders place the info structure adjacent
 * to or inside the already-tightened image pages. Reapplying RW+NX there can
 * silently strip execute permissions from .text.
 *
 * PTE format (64-bit):
 *   Low  dword: phys_addr[31:12] | flags[11:0]
 *   High dword: phys_addr[63:32] | NX (bit 31)
 *
 * Page table overflow protection: max 1048576 pages (~4 GiB)
 * ================================================================ */
setup_page_tables_wx:
    push %ebx
    push %esi
    push %edi
    push %ebp

    /* ---- Clear all page table memory ---- */
    /* pml4 + pdpt + pd_pool + pt_pool =
     * 1×4096 + 1×4096 + 4×4096 + 2048×4096 = 8,413,184 bytes */
    mov $pml4, %edi
    xor %eax, %eax
    mov $2103296, %ecx              /* 8,413,184 / 4 = 2,103,296 dwords */
    rep stosl

    /* ---- Wire up the hierarchy ---- */

    /* PML4[0] → PDPT  (Present + Write, NX=0) */
    mov $pdpt, %eax
    or $0x3, %eax
    mov %eax, (pml4)
    movl $0, (pml4 + 4)

    /* PDPT[0..3] → pd_pool[0..3]  (Present + Write, NX=0) */
    mov $0, %ebp                    /* PDPT entry index */
.Lpd_setup:
    cmp $4, %ebp
    jge .Lpd_done
    mov %ebp, %eax
    shl $12, %eax                   /* PT offset = index × 4096 */
    add $pd_pool, %eax              /* PD physical address */
    or $0x3, %eax                   /* Present + Write */
    mov %ebp, %esi
    shl $3, %esi                    /* PDPT byte offset = index × 8 */
    mov %eax, pdpt(%esi)            /* PDPT entry low dword */
    movl $0, pdpt+4(%esi)           /* PDPT entry high dword (NX=0) */
    inc %ebp
    jmp .Lpd_setup
.Lpd_done:

    /* pd_pool[0..2047] → pt_pool[0..2047]  (Present + Write, NX=0) */
    mov $0, %ebp                    /* PD entry index across all PD pages */
.Lpt_setup:
    cmp $2048, %ebp
    jge .Lpt_done
    mov %ebp, %eax
    shl $12, %eax                   /* PT offset = index × 4096 */
    add $pt_pool, %eax              /* PT physical address */
    or $0x3, %eax                   /* Present + Write */
    mov %ebp, %esi
    shl $3, %esi                    /* PD byte offset = index × 8 */
    mov %eax, pd_pool(%esi)         /* PD entry low dword */
    movl $0, pd_pool+4(%esi)        /* PD entry high dword (NX=0) */
    inc %ebp
    jmp .Lpt_setup
.Lpt_done:

    /* ---- Determine NX flag for high dword ---- */
    cmpl $0, (nx_supported)
    jz .Lnx_zero
    movl $0x80000000, (nx_high_bits) /* Bit 31 of high dword = NX */
    jmp .Lnx_resolved
.Lnx_zero:
    movl $0, (nx_high_bits)
.Lnx_resolved:

    /* Provide a broad near-4 GiB RW+NX identity map first so retained-C code
     * can reach firmware structures (ACPI/XSDT/DMAR/IVRS, EBDA scan,
     * bootloader metadata, and high MMIO regions such as VT-d and xAPIC.
     * Section-specific mappings below tighten the hypervisor image back to W^X. */
    xor %eax, %eax
    mov $0xFFFFF000, %ebx           /* Just under 4 GiB */
    mov $0x3, %ecx                  /* Present + Write */
    mov (nx_high_bits), %edx        /* NX */
    call map_page_range

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
 * Overflow protection: stops if page index >= 1048576 (beyond pt_pool)
 * ================================================================ */
map_page_range:
.Lmap_range_loop:
    cmp %ebx, %eax
    jae .Lmap_range_done
    /* Compute flat PTE address: pt_pool + (phys >> 12) × 8 */
    mov %eax, %esi
    shr $12, %esi
    cmp $1048576, %esi              /* 2048 PTs × 512 entries ~= 4 GiB */
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
    cmp $1048576, %esi
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
boot_msg_32:
    .asciz "FBVBS: boot32 reached\n"
boot_msg_lm_ok:
    .asciz "FBVBS: long mode supported\n"
boot_msg_pt_ready:
    .asciz "FBVBS: page tables ready\n"
boot_msg_cr4_ready:
    .asciz "FBVBS: CR4.PAE enabled\n"
boot_msg_cr3_ready:
    .asciz "FBVBS: CR3 loaded\n"
boot_msg_efer_ready:
    .asciz "FBVBS: EFER updated\n"
boot_msg_enter_64:
    .asciz "FBVBS: entering 64-bit mode\n"
boot_msg_64_entry:
    .asciz "FBVBS: boot64 entry raw\n"
boot_msg_no_lm:
    .asciz "FBVBS: long mode unavailable\n"
boot_msg_64:
    .asciz "FBVBS: boot64 reached\n"

.align 8
boot_gdt:
    .quad 0x0000000000000000        /* Null descriptor */
    /* Pre-mark descriptors as accessed before paging tightens .rodata to R+NX.
     * Real CPUs/KVM may set the accessed bit on control transfers or segment
     * loads; leaving it clear would turn the long-mode handoff into a fault
     * once the boot GDT becomes read-only. */
    .quad 0x00CF9B000000FFFF        /* 32-bit flat boot code (accessed) */
    .quad 0x00CF93000000FFFF        /* 32-bit/64-bit flat data (accessed) */
    .quad 0x00AF9B000000FFFF        /* 64-bit flat code (accessed) */
boot_gdt_end:

boot_gdt_pointer_32:
    .word boot_gdt_end - boot_gdt - 1
    .long boot_gdt

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

/* Page tables: PML4, PDPT, 4 PD tables, and 2048 PT tables (~4 GiB coverage) */
.align 4096
pml4:
    .space 4096
pdpt:
    .space 4096
pd_pool:
    .space 16384
pt_pool:
    .space 8388608                  /* 2048 × 4096 = 2048 PTs, 1,048,576 pages */

/* Stack with guard page */
.align 4096
stack_guard:
    .space 4096                     /* NOT mapped → page fault on overflow */
stack_bottom:
    .space 16384                    /* 16 KiB stack */
stack_top:

/* Mark stack as non-executable */
.section .note.GNU-stack,"",@progbits
