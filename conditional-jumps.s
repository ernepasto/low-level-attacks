; if [x] is 0x7f454c46: y = [x+4] + [x+8] + [x+12] else if [x] is 0x00005A4D: y = [x+4] - [x+8] - [x+12] else: y = [x+4] * [x+8] * [x+12]
; x = rdi, y = rax
;
.intel_syntax noprefix
.global _start
_start:
;
mov rax, 0
;
mov ecx, 0x7f454c46
cmp [edi], ecx
jne first
mov eax, [edi+4]
add eax, [edi+8]
add eax, [edi+12]
jmp done
;
first:
mov ecx, 0x00005A4D
cmp [edi], ecx
jne second
mov eax, [edi+4]
sub eax, [edi+8]
sub eax, [edi+12]
jmp done
;
second:
mov eax, [edi+4]
imul eax, [edi+8]
imul eax, [edi+12]
;
done:
