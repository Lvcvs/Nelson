#!/usr/bin/python
# -*- coding: utf-8 -*-
import os
import sys
import socket

end = '\033[0m'
red = '\033[1;31m'
bright_green = '\033[1;32m'

# in caso di un output troppo lungo questo aumenta le dimensioni del terminale
def check_len_message(message):
    columns = os.popen('stty size', 'r').read().split()[1]
    colors = ['\033[0m','\033[1;31m','\033[4m','\033[1;32m','\033[1;33m']

    for e in colors:
        if e in message:
            message = message.replace(e,"")

    if int(len(message)) >= int(columns):
        columns = int(len(message)) + 1
        sys.stdout.write("\x1b[8;{rows};{cols}t".format(rows=24, cols=columns)) # grandezza terminale

def gethost(target):
    print("[#] %s"%(target))
    try:
        gethost = socket.gethostbyaddr(target)[0]
    except socket.herror:
        gethost = socket.getfqdn(target)
    except socket.gaierror:
        print("[%s-%s] Indirizzo non valido"%(red,end))
    try:
        if gethost == target:
            print("[%s-%s] Nessun hostname non trovato"%(red,end))
        else:
            message = "[%s+%s] %s"%(bright_green,end, gethost)
            check_len_message(message)
            print(message)
    except UnboundLocalError:
        pass
    print("")
