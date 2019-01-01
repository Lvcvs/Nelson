#!/usr/bin/python
# -*- coding: utf-8 -*-
import os
import sys
import json
import httplib
import urllib2
from scapy.all import *

end = '\033[0m'
red = '\033[1;31m'
bright_green = '\033[1;32m'
bright_yellow = '\033[1;33m'

def final(arg=None):
    if arg == "Exit":
        exit()
    else:
        import nelson as n
        n.main()

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

def get_ccr(target):
    try: # codice di verifica
        response = urllib2.urlopen("http://ip-api.com/json/%s"%(target))
    except (httplib.BadStatusLine,urllib2.URLError,socket.timeout):
        print("[%s-%s] Connessione a internet non riuscita"%(red,end))
        final()
    except KeyboardInterrupt:
        print("\r[%s-%s] Interrotto\n"%(red,end))
        final()

    try: # preparativi
        data = response.read()
        values = json.loads(data)
    except KeyboardInterrupt:
        print("\r[%s-%s] Interrotto\n"%(red,end))
        final()

    try: # informazioni indirizzo IP
        country = values['country']
    except KeyError:
        country = ""
    try: # informazioni indirizzo IP
        regionName = values['regionName']
    except KeyError:
        regionName = ""
    try: # codice postale
        zip = values['zip']
    except KeyError:
        zip = ""

    results = "%s / %s %s"%(country, zip, regionName)

    if regionName == "" or country == "":
        results = "-"

    return results

def trace(target):
    print("\n[#] Trace\n")
    print("[#] Target: %s"%(target))
    print("[%s*%s] Avvio...\n"%(bright_yellow,end))

    # Questo ottiene i primi 3 numeri dell'indirizzo ip locale
    base_ip = ""
    try:
        localip = [l for l in ([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][:1], [[(s.connect(('8.8.8.8', 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) if l][0][0]
    except (socket.herror,socket.gaierror):
        localip = netifaces.ifaddresses(str(iface))[netifaces.AF_INET][0]['addr']
    except socket.error:
        localip = None
    if localip != None:
        for e in localip.split(".")[:3]:
            base_ip += e + "."
    ###
    for i in range(1, 28):
        try:
            results = 0
            pkt = IP(dst=target, ttl=i) / UDP(dport=33434) # prepara il pacchetto
            reply = sr1(pkt, verbose=0) # Spedisce il pacchetto e riceve una risposta
            if reply is None:
                print("\r  \n[%s-%s] Terminato\n"%(red,end))
                final()
            elif reply.type == 3:
                if results == 0:
                    print("[%s-%s] Nessun risultato"%(red,end))
                print("[%s+%s] Terminato\n"%(bright_green,end))
                final()
            else:
                try:
                    hostname = socket.gethostbyaddr(reply.src)[0] # ottiene l'hostname dall'indirizzo
                except socket.herror:
                    hostname = socket.getfqdn(reply.src)
                    if hostname == reply.src:
                        hostname = "-"

                results += 1

                connected = reply.src

                base_ip_connected = ""
                for e in connected.split(".")[:3]:
                    base_ip_connected += e + "."

                print("[%s+%s] Address       > %s"%(bright_green,end, connected))

                type = "Public"
                ccr_message = ""

                if base_ip_connected == base_ip:
                    type = "Private"

                if connected == localip:
                    type = "Local"

                print("[#] Address Type  > %s"%(type))

                if type == "Public":
                    CCR = get_ccr(connected)
                    ccr_message = " Country / Region > %s"%(CCR)
                    check_len_message(ccr_message)
                    print(ccr_message)

                message = " Hostname         > %s"%(hostname)
                check_len_message(message)
                print(message)
                print("")

        except socket.gaierror:
            print("[%s-%s] Indirizzo sconosciuto\n"%(red,end))
            final()
        except KeyboardInterrupt:
            print("\r[%s-%s] Interrotto\n"%(red,end))
            final()
        except: # select.error, IOError, OSError # Exit error codes
            raise
            final("Exit")
