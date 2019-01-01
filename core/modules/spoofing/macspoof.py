#!/usr/bin/python
# -*- coding: utf-8 -*-
import os
import re
import sys
import uuid
import random
from datetime import datetime

end = '\033[0m'
red = '\033[1;31m'
bright_green = '\033[1;32m'
bright_yellow = '\033[1;33m'

def final():
    import nelson as n
    n.main()

def DEFAULT_MAC(iface): # indirizzo default
    try:
        return os.popen("ethtool -P %s"%(iface)).read().split()[2]
    except IndexError:
        print("[%s-%s] Interfaccia di rete non valida"%(red,end))
        final()

def CHECKSPOOF(): # codice di verifica
    if os.path.isfile("core/modules/output/spoofed"):
        return True
    else:
        return False

def randomMAC(): # genera indirizzo mac random
    return [ 0x00, 0x16, 0x3e,
        random.randint(0x00, 0x7f),
        random.randint(0x00, 0xff),
        random.randint(0x00, 0xff) ]
def MACprettyprint(mac): # riordina mac
    return ':'.join(map(lambda x: "%02x" % x, mac))

def status(): # informazioni macspoof
    check = CHECKSPOOF()
    if check == True:
        stat = bright_green+"Attivo"+end
    else:
        stat = red+"Non Attivo"+end
    print("[#] Macspoof")
    print("[%s*%s] Stato: %s"%(bright_yellow,end, stat))
    if os.path.isfile("core/modules/output/spoofed"):
        IFACE_SPOOFED = open("core/modules/output/spoofed","r").read().split()[0]
        MAC_SPOOFED = open("core/modules/output/spoofed","r").read().split()[1]
        get_time = open("core/modules/output/spoofed","r").read().split()[2]
        date = get_time.split("--")[0]
        time = get_time.split("--")[1]
        print("[%s+%s] Avviato               > %s (%s)"%(bright_green,end, time, date))
        print("[%s+%s] Interfaccia Nascosta  > %s"%(bright_green,end, IFACE_SPOOFED))
        print("[%s*%s] Indirizzo Mac Attuale > %s"%(bright_yellow,end, MAC_SPOOFED))
        print("[%s*%s] Indirizzo Mac Default > %s"%(bright_yellow,end, DEFAULT_MAC(IFACE_SPOOFED)))

def spoof(iface): # avvia
    DEFAULT_MAC(iface)
    os.system("service network-manager stop")
    MAC_SPOOFED = MACprettyprint(randomMAC())
    os.system("ifconfig %s hw ether %s"%(iface, MAC_SPOOFED))
    os.system("service network-manager start")
    time = datetime.now().strftime('%d.%m.%Y--%H:%M:%S')
    os.system("echo '%s %s %s' > core/modules/output/spoofed"%(iface, MAC_SPOOFED, time))
    print("[%s+%s] Macspoof Avviato"%(bright_green,end))

def unspoof(iface): # ferma
    DEFAULT_MAC(iface)
    os.system("service network-manager stop")
    os.system("ifconfig %s hw ether %s"%(iface, DEFAULT_MAC(iface)))
    os.system("service network-manager start")
    if os.path.isfile("core/modules/output/spoofed"):
        os.system("rm core/modules/output/spoofed")
    print("[%s+%s] Macspoof Fermato"%(bright_green,end))

def check(arg=None): # verifica se attivo
    check_spoof = CHECKSPOOF()
    if check_spoof == True:
        if arg == "startup": # avvio nelson
            if os.path.isfile("core/modules/output/tor_spoofed") == False:
                print("")
            print("[%s+%s] Macspoof Attivo"%(bright_green,end))
        else: # uscita nelson
            print("[%s!%s] Macspoof Attivo"%(red,end))
    else:
        pass
