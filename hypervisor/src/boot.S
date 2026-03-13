/* FBVBS Hypervisor Boot Entry Point
 *
 * This boot code handles:
 * - Multiboot2 header for bootloader compatibility
 * - 32-bit to 64-bit transition
 * - Proper stack initialization
 * - Interrupt disabling at entry
 * - Multiboot information preservation
 * - Dynamic page table setup for large binaries
 */

.section .multiboot_header, "a"
.align 8

/* Multiboot2 header with information request tags */
multiboot_header:
    .long 0xE85250D6                /* magic number */
    .long 0                         /* architecture (i386) */
    .long multiboot_header_end - multiboot_header  /* header length */
    .long -(0xE85250D6 + 0 + (multiboot_header_end - multiboot_header))  /* checksum */

    /* Request basic memory information */
    .word 1                         /* type: information request */
    .word 0                         /* flags */
    .long 12                        /* size */
    .long 4                         /* memory map tag */
    .long 6                         /* memory map entry tag */

    /* Request memory map */
    .word 1                         /* type: information request */
    .word 0                         /* flags */
    .long 12                        /* size */
    .long 6                         /* memory map tag */
    .long 0                         /* padding */

    /* Request basic memory info */
    .word 1                         /* type: information request */
    .word 0                         /* flags */
    .long 12                        /* size */
    .long 4                         /* basic memory info tag */
    .long 0                         /* padding */

    /* Request boot device */
    .word 1                         /* type: information request */
    .word 0                         /* flags */
    .long 12                        /* size */
    .long 5                         /* boot device tag */
    .long 0                         /* padding */

    /* Request command line */
    .word 1                         /* type: information request */
    .word 0                         /* flags */
    .long 12                        /* size */
    .long 1                         /* command line tag */
    .long 0                         /* padding */

    /* Request module information */
    .word 1                         /* type: information request */
    .word 0                         /* flags */
    .long 12                        /* size */
    .long 3                         /* module tag */
    .long 0                         /* padding */

    /* Request framebuffer information */
    .word 1                         /* type: information request */
    .word 0                         /* flags */
    .long 12                        /* size */
    .long 8                         /* framebuffer tag */
    .long 0                         /* padding */

    /* end tag */
    .word 0                         /* type */
    .word 0                         /* flags */
    .long 8                         /* size */
multiboot_header_end:

.section .text
.code32
.global _start
.type _start, @function

/* 32-bit entry point - called by bootloader */
_start:
    /* Disable interrupts immediately */
    cli

    /* Save Multiboot information pointer (ebx) - use edi for 64-bit transition */
    mov %ebx, %edi

    /* Check if we're in 32-bit protected mode */
    /* Set up minimal 32-bit stack */
    mov $stack_top, %esp
    and $-16, %esp                  /* 16-byte align for ABI compliance */

    /* Check for long mode support */
    call check_long_mode
    test %eax, %eax
    jz .Lno_long_mode_error

    /* Set up page tables dynamically based on binary size */
    call setup_page_tables_dynamic

    /* Enable PAE */
    mov %cr4, %eax
    or $0x20, %eax                  /* CR4.PAE */
    mov %eax, %cr4

    /* Load page table */
    mov $pml4, %eax
    mov %eax, %cr3

    /* Enable long mode */
    mov $0xC0000080, %ecx           /* EFER MSR */
    rdmsr
    or $0x100, %eax                 /* EFER.LME */
    wrmsr

    /* Enable paging and protected mode */
    mov %cr0, %eax
    or $0x80000001, %eax            /* CR0.PG | CR0.PE */
    mov %eax, %cr0

    /* Load 64-bit GDT */
    lgdt gdt64_pointer

    /* Far jump to 64-bit code, passing Multiboot info in rdi */
    ljmp $0x08, $start64

.Lno_long_mode_error:
    /* Print error message if possible, then halt */
    mov $error_no_long_mode, %esi
    call print_string_32
    jmp .Lhalt_forever

.code64
start64:
    /* Set up 64-bit segment registers */
    xor %rax, %rax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %gs
    mov %ax, %ss

    /* Set up 64-bit stack with proper alignment */
    mov $stack_top, %rsp
    and $-16, %rsp                  /* 16-byte align for ABI compliance */

    /* Clear base pointer */
    xor %rbp, %rbp

    /* Pass Multiboot information to kernel (edi contains pointer from 32-bit) */
    /* Zero-extend edi to rdi (upper 32 bits are undefined after far jump) */
    mov %edi, %edi                  /* Zero-extend edi to rdi */
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

/* Print string in 32-bit mode (for error messages) */
print_string_32:
    push %ebx
    push %esi
    mov $0xB8000, %edi              /* VGA text buffer */
    mov $0x0F, %ah                  /* White on black */
.Lprint_loop:
    lodsb
    test %al, %al
    jz .Lprint_done
    stosw
    jmp .Lprint_loop
.Lprint_done:
    pop %esi
    pop %ebx
    ret

/* Check if CPU supports long mode */
check_long_mode:
    push %ebx

    /* Check for CPUID support */
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

    /* Check for extended CPUID */
    mov $0x80000000, %eax
    cpuid
    cmp $0x80000001, %eax
    jb .Lno_long_mode_check

    /* Check for long mode */
    mov $0x80000001, %eax
    cpuid
    and $0x20000000, %edx           /* CPUID.80000001H:EDX.LM */
    shr $29, %edx
    mov %edx, %eax
    jmp .Lcheck_done

.Lno_cpuid:
.Lno_long_mode_check:
    xor %eax, %eax

.Lcheck_done:
    pop %ebx
    ret

/* Set up page tables dynamically based on binary size */
setup_page_tables_dynamic:
    push %ebx
    push %esi
    push %edi

    /* Calculate binary size (end - start) */
    mov $_binary_end, %eax
    sub $_binary_start, %eax
    add $0xFFF, %eax                /* Round up to page boundary */
    and $0xFFFFF000, %eax
    mov %eax, %ebx                  /* ebx = binary size in bytes */

    /* Calculate number of pages needed */
    shr $12, %ebx                   /* ebx = number of 4KB pages */

    /* Clear page tables */
    mov $pml4, %edi
    xor %eax, %eax
    mov $4096, %ecx
    rep stosl

    mov $pdpt, %edi
    mov $4096, %ecx
    rep stosl

    mov $pd, %edi
    mov $4096, %ecx
    rep stosl

    mov $pt, %edi
    mov $4096, %ecx
    rep stosl

    /* Set up PML4 */
    mov $pdpt, %eax
    or $0x3, %eax                   /* Present + Writable */
    mov %eax, (pml4)

    /* Set up PDPT */
    mov $pd, %eax
    or $0x3, %eax                   /* Present + Writable */
    mov %eax, (pdpt)

    /* Set up PD (2MB pages) */
    mov $pt, %eax
    or $0x3, %eax                   /* Present + Writable */
    mov %eax, (pd)

    /* Set up PT (4KB pages) - map binary + Multiboot info + framebuffer */
    mov $pt, %edi
    mov %ebx, %ecx                  /* Number of pages to map */
    xor %eax, %eax
    or $0x3, %eax                   /* Present + Writable */
.Lpt_loop:
    test %ecx, %ecx
    jz .Lpt_done
    mov %eax, (%edi)
    add $0x1000, %eax
    add $8, %edi
    dec %ecx
    jmp .Lpt_loop
.Lpt_done:

    /* Map additional pages for Multiboot info (at least 1 page) */
    mov $pt, %edi
    mov %ebx, %eax
    shl $3, %eax                    /* Convert page index to byte offset */
    add %eax, %edi                  /* edi = pt + (ebx * 8) */
    mov $0x3, %eax                  /* Present + Writable */
    mov %eax, (%edi)

    /* Map additional pages for framebuffer (at least 1 page) */
    mov $pt, %edi
    mov %ebx, %eax
    inc %eax                        /* Next page after Multiboot info */
    shl $3, %eax                    /* Convert page index to byte offset */
    add %eax, %edi                  /* edi = pt + ((ebx+1) * 8) */
    mov $0x3, %eax                  /* Present + Writable */
    mov %eax, (%edi)

    pop %edi
    pop %esi
    pop %ebx
    ret

/* Error messages */
.section .rodata
error_no_long_mode:
    .asciz "ERROR: CPU does not support 64-bit long mode"

.section .bss
.align 4096
pml4:
    .space 4096
pdpt:
    .space 4096
pd:
    .space 4096
pt:
    .space 4096

.align 16
stack_bottom:
    .space 16384                    /* 16KB stack */
stack_top:

.section .rodata
.align 8
gdt64:
    .quad 0x0000000000000000        /* null descriptor */
    .quad 0x00AF9A000000FFFF        /* 64-bit code segment */
    .quad 0x00AF92000000FFFF        /* 64-bit data segment */
gdt64_end:

gdt64_pointer:
    .word gdt64_end - gdt64 - 1
    .quad gdt64

/* Binary size symbols (defined by linker) */
.global _binary_start
.global _binary_end

.section .note.GNU-stack,"",@progbits
