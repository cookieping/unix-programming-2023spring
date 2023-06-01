quick_sort:
    push    rbp
    mov     rbp, rsp
    sub     rsp, 0x10
    mov     rdx, rsi
    dec     rdx
    xor     rsi, rsi
    call    quicksort
    xor     rax, rax
    leave
    ret
quicksort:
    push    rbp
    mov     rbp, rsp
    sub     rsp, 0x30
    mov     QWORD PTR [rbp-0x10],rsi
    mov     QWORD PTR [rbp-0x18], rdx
    cmp     rsi, rdx
    jge     L1
    xor     rax, rax
    call    partition
    mov     QWORD PTR [rbp-0x20], rax
    mov     rsi, QWORD PTR [rbp-0x10]
    mov     rdx, QWORD PTR [rbp-0x20]
    dec     rdx
    call    quicksort
    mov     rsi, QWORD PTR [rbp-0x20]
    inc     rsi
    mov     rdx, QWORD PTR [rbp-0x18]
    call    quicksort
L1:
    leave
    ret

partition:
    push    rbp
    mov     rbp, rsp
    sub     rsp, 0x10
    mov     r8, QWORD PTR [rdi+rdx*8]
    mov     r9, rsi
    dec     r9
    mov     r10, rsi
FORLOOP:
    cmp     r10, rdx
    jge     AFTERFORLOOP

    cmp     [rdi+r10*8], r8
    jge     L2
    inc     r9
    mov     r11, QWORD PTR [rdi+r9*8]
    mov     r12, QWORD PTR [rdi+r10*8]
    mov     QWORD PTR [rdi+r9*8], r12
    mov     QWORD PTR [rdi+r10*8], r11
L2:
    inc     r10
    jmp     FORLOOP

AFTERFORLOOP:
    inc     r9
    mov     r11, QWORD PTR [rdi+r9*8]
    mov     r12, QWORD PTR [rdi+rdx*8]
    mov     QWORD PTR [rdi+r9*8], r12
    mov     QWORD PTR [rdi+rdx*8], r11

    mov     rax, r9
    leave
    ret
