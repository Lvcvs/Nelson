#!/usr/bin/python
# -*- coding: utf-8 -*-
import os
import time
import json
import socket
import urllib2
import bluetooth
from datetime import datetime

end = '\033[0m'
red = '\033[1;31m'
bright_green = '\033[1;32m'
bright_yellow = '\033[1;33m'

def final():
    import nelson as n
    n.main()

def check_conn():
    socket.setdefaulttimeout(.1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        s.close()
        return True
    except socket.error:
        s.close()
        return False

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

# ottiene il nome del venditore tramite indirizzo MAC
def get_mac_vendor(mac):
    socket.setdefaulttimeout(1)
    vendor = "-"
    try:
        response = urllib2.urlopen("http://macvendors.co/api/%s"%(mac))
        data = response.read()
        values = json.loads(data)
        vendor = values['result']['company']
    except:
        raise

    return vendor

def scan():
    print("\n[#] Bluescan\n")
    s_time = datetime.now().strftime('%H:%M:%S')
    start_ = time.time() # avvio

    try:
        print("[%s+%s] Avvio scansione bluetooth: %s"%(bright_green,end, s_time))
        nearby_devices = bluetooth.discover_devices(lookup_names=True) # scansione
    except OSError:
        print("[%s-%s] Interfaccia bluetooth non trovata\n"%(red,end))
        final()
    except KeyboardInterrupt:
        print("\r  \n[%s-%s] Interrotto\n"%(red,end))
        final()

    check_int_conn = check_conn()

    symbol = "%s+%s"%(bright_green,end)
    if len(nearby_devices) == 0: # codice di verifica
        symbol = "%s-%s"%(red,end)

    print("\n[%s] Dispositivi: %s"%(symbol, len(nearby_devices)))

    if len(nearby_devices) != 0:
        print("")

        for addr, name in nearby_devices:
            vend = None
            if check_int_conn == True:
                vendor = get_mac_vendor(addr)
                vend = "[%s+%s] Vendor: -# %s"%(bright_green,end, vendor)

            name = "[%s+%s] Nome:   -# %s"%(bright_green,end, name)
            addr = "[%s+%s] MAC:    -# %s"%(bright_green,end, addr.upper())

            srvc = False
            try:
                services = bluetooth.find_service(address=addr)
                srvc = True
            except:
                pass

            check_len_message(name)
            check_len_message(addr)

            print(name)
            print(addr)

            if srvc == True:
                for svc in services:
                    msgs = [
                    "[%s+%s] Nome Servizio: %s"%(bright_green,end, svc["name"]),
                    "  > Host:        %s"%(svc["host"]),
                    "  > ID:          %s"%(svc["service-id"]),
                    "  > Provider:    %s"%(svc["provider"]),
                    "  > Protocollo:  %s"%(svc["protocol"]),
                    "  > Descrizione: %s"%(svc["description"]),
                    "  > Canale/PSM:  %s"%(svc["port"]),
                    "  > Classe:      %s"%(svc["service-classes"]),
                    "  > Profilo:     %s"%(svc["profiles"])
                    ]
                    for e in msgs:
                        check_len_message(e)
                        print(e)

            if check_int_conn == True:
                check_len_message(vend)
                print(vend)

            if len(nearby_devices) > 1:
                print("")

    end_ = time.time() # termine
    elapsed = round((end_-start_), 2)
    e_time = datetime.now().strftime('%H:%M:%S')
    print("\n[%s+%s] Scansione terminata: %s"%(bright_green,end, e_time))
    print("[%s*%s] Durata: %s secondi\n"%(bright_yellow,end, elapsed))
