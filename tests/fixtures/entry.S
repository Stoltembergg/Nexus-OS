#ifdef NT
.text
.globl entry
entry:
    sub $40, %rsp
    call probe
    mov %eax, %edx
    mov $-1, %r10
    mov $0x2c, %eax
    syscall
    ud2
.globl nt_write
nt_write:
    mov %rcx, %r10
    mov $8, %eax
    syscall
    ret
#else
.text
.globl _start
_start:
    call probe
    mov %eax, %edi
    mov $60, %eax
    syscall
    ud2
#endif

.globl context_probe
context_probe:
    push %rbx
    push %rbp
    push %r12
    push %r13
    push %r14
    push %r15
    push %rdi
    push %rsi
    sub $40, %rsp
    movdqu %xmm6, 16(%rsp)
    stmxcsr 8(%rsp)
    fnstcw 12(%rsp)
    movl $0x2000, (%rsp) // hostile: exceptions unmasked, altered rounding
    ldmxcsr (%rsp)
    movw $0x077f, (%rsp)
    fldcw (%rsp)
    fld1
    // Exercise a returning syscall before yield, with user FP controls active.
    mov $999, %eax
    syscall
#ifdef NT
    mov $0xc0000002, %edx
    cmp %rdx, %rax
#else
    cmp $-38, %rax
#endif
    jne fail
    mov $0x123, %rbx
    mov $0x234, %rbp
    mov $0x345, %r12
    mov $0x456, %r13
    mov $0x567, %r14
    mov $0x678, %r15
    mov $0x789, %rdi
    mov $0x89a, %rsi
    mov $0x9ab, %rdx
    mov $0xabc, %r8
    mov $0xbcd, %r9
    mov $0xcde, %r10
    mov $0x12345678, %eax
    movq %rax, %xmm0
    movq %rax, %xmm6
#ifdef NT
    mov $0x50, %eax
#else
    mov $24, %eax
#endif
    std
    syscall
    test %rax, %rax
    jnz fail
    pushfq
    pop %rax
    test $1024, %eax
    jz fail
    cld
    cmp $0x123, %rbx
    jne fail
    cmp $0x234, %rbp
    jne fail
    cmp $0x345, %r12
    jne fail
    cmp $0x456, %r13
    jne fail
    cmp $0x567, %r14
    jne fail
    cmp $0x678, %r15
    jne fail
    cmp $0x789, %rdi
    jne fail
    cmp $0x89a, %rsi
    jne fail
    cmp $0x9ab, %rdx
    jne fail
    cmp $0xabc, %r8
    jne fail
    cmp $0xbcd, %r9
    jne fail
    cmp $0xcde, %r10
    jne fail
    movq %xmm0, %rax
    cmp $0x12345678, %rax
    jne fail
    movq %xmm6, %rax
    cmp $0x12345678, %rax
    jne fail
    stmxcsr (%rsp)
    cmpl $0x2000, (%rsp)
    jne fail
    fnstcw (%rsp)
    cmpw $0x077f, (%rsp)
    jne fail
    fstps (%rsp)
    cmpl $0x3f800000, (%rsp)
    jne fail
    xor %eax, %eax
    jmp done
fail:
    cld
    mov $112, %eax
done:
    ldmxcsr 8(%rsp)
    fldcw 12(%rsp)
    movdqu 16(%rsp), %xmm6
    add $40, %rsp
    pop %rsi
    pop %rdi
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %rbp
    pop %rbx
    ret
