=Low-level attacks
I low-level attacks in C sfruttano vulnerabilità nella gestione della memoria per eseguire codice arbitrario o manipolare il flusso di esecuzione di un programma. Tra i più noti ci sono il buffer overflow e la shellcode injection.
Un buffer overflow si verifica quando un programma scrive più dati di quanti ne siano stati allocati per un determinato buffer in memoria, sovrascrivendo dati adiacenti e potenzialmente modificando il comportamento del programma.
La shellcode injection è una tecnica che sfrutta un buffer overflow per eseguire codice malevolo all'interno di un programma vulnerabile. L'attaccante inserisce un payload eseguibile (shellcode) nel buffer e manipola il valore del program counter per far sì che l’esecuzione passi al codice iniettato.
