# if x is even then y = 1 else y = 0 | Where: x = rdi and y = rax
.intel_syntax noprefix
.global _start
_start:
and rax, 0x0
and dil, 0x1
or al, dil
xor al, 0x1
and al, 0x1
