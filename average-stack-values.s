# Without using pop, calculate the average of 4 consecutive quad words stored on the stack. Push the average on the stack.
.intel_syntax noprefix
.global _start
_start:
mov rdx, 0x0
mov rcx, 0x4
mov rax, [rsp]+0
add rax, [rsp]+8
add rax, [rsp]+16
add rax, [rsp]+24
div rcx
push rax
