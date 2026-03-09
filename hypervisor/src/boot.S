.section .text
.global _start
.type _start, @function

_start:
    xor %rbp, %rbp
    call fbvbs_kernel_main

.Lhalt:
    hlt
    jmp .Lhalt

.section .note.GNU-stack,"",@progbits
