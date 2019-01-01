#!/usr/bin/python
# -*- coding: utf-8 -*-
# Autore: susmithHCK (https://github.com/susmithHCK)
# Modificato da: Skull00 (https://github.com/Skull00)
import os
import sys
import time
import httplib
from datetime import datetime

end = '\033[0m'
red = '\033[1;31m'
bright_green = '\033[1;32m'
bright_yellow = '\033[1;33m'

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

def final():
    import nelson as n
    n.main()

def check(target, path):
    try:
        conn = httplib.HTTPConnection(target)
        conn.request("HEAD", path)
        return conn.getresponse().status
    except (StandardError,httplib.CannotSendRequest):
        return "-"
    except KeyboardInterrupt:
        print("\n\n[%s-%s] Interrotto\n"%(red,end))
        final()

def scan(target,directory):
    maxlen = len(directory)
    result = None

    i = 0
    tested = 0
    for i in range(maxlen):
        c_dir = directory[i].rstrip('\n')
        rcode = check(target,c_dir)
        code = str(rcode)

        tested += 1
        sys.stdout.write("\r[#] > %s (%s/%s)"%(target, tested, maxlen))
        sys.stdout.flush()

        if rcode < 400:
            result = "[%s+%s] > %s: %s"%(bright_green,end, bright_green+code+end, target+c_dir)

    if result != None:
        check_len_message(result)
        print("\n%s\n"%(result))
    else:
        print("\n[%s-%s] > Nessun risultato\n"%(red,end))

def main(targets):
    print("\n[#] CPScan\n")

    to_scan = []

    for target in targets:
        message = "[%s*%s] Verifico indirizzo: %s"%(bright_yellow,end, target)
        check_len_message(message)
        sys.stdout.write(message)
        sys.stdout.flush()
        ccode = check(target,"/")

        if ccode < 400:
            sys.stdout.write(" [%sOK%s]-[%s]\n"%(bright_green,end, ccode))
            sys.stdout.flush()
            to_scan.append(target)
        else:
            sys.stdout.write(" [%sFAIL%s]-[%s]\n"%(red,end, ccode))
            sys.stdout.flush()

    if len(to_scan) == 0:
        print("\n[%s-%s] 0 indirizzi validi da scansionare\n"%(red,end))
        final()

    if len(to_scan) == 1:
        print("\n[#] In scansione: %s indirizzo"%(len(to_scan)))
    else:
        print("\n[#] In scansione: %s indirizzi"%(len(to_scan)))

    try:
        f = open("core/modules/lists/directories.txt","r")
        directory = []
        for line in f:
            directory.append(line)
    except KeyboardInterrupt:
        print("\n[%s-%s] Interrotto\n"%(red,end))
        final()

    print("[%s+%s] %s Directories caricate"%(bright_green,end, len(directory)))

    start_ = time.time()
    s_time = datetime.now().strftime('%H:%M:%S')
    print("\n[%s+%s] Scansione avviata: %s\n"%(bright_green,end, s_time))

    for target in to_scan:
        scan(target,directory)

    end_ = time.time()
    elapsed = round((end_-start_), 2)
    e_time = datetime.now().strftime('%H:%M:%S')
    print("[%s+%s] Scansione terminata: %s"%(bright_green,end, e_time))
    print("[%s*%s] Durata: %s secondi\n"%(bright_yellow,end, elapsed))

    final()
