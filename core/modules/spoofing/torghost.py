#!/usr/bin/python
# -*- coding: utf-8 -*-
# Autore: SusmithHCK
# Sito: www.khromozome.com
# Hacker's QandA forum: https://www.askthehackers.com
# Modificato da: Skull00 (https://www.github.com/Skull00)
import os
import sys
import time
import commands
import requests
from commands import getoutput
from stem import Signal
from stem.control import Controller
from datetime import datetime

end = '\033[0m'
red = '\033[1;31m'
bright_green = '\033[1;32m'
bright_yellow = '\033[1;33m'

TorrcCfgString = """
##/////ADDED BY TORGHOST ///
VirtualAddrNetwork 10.0.0.0/10
AutomapHostsOnResolve 1
TransPort 9040
DNSPort 53
ControlPort 9051
"""
resolvString = "nameserver 127.0.0.1"
Torrc = "/etc/tor/torrc"
resolv = "/etc/resolv.conf"

def final():
    import nelson as n
    n.main()

def CHECKSPOOF():
    if os.path.isfile("core/modules/output/tor_spoofed"):
        return True
    else:
        return False

def ip():
    failed = 0
    ipadd = None
    while ipadd == None:
        try:
            ipadd = requests.get('http://ip.42.pl/raw').text
        except:
            ipadd = None
            try:
                time.sleep(.1)
            except KeyboardInterrupt:
                pass
            failed += 1
            if failed == 50:
                ipadd = "-"
                break
            continue
    return ipadd

def status():
    check = CHECKSPOOF()
    if check == True:
        stat = bright_green+"Attivo"+end
    else:
        stat = red+"Non Attivo"+end
    print("[#] Torghost")
    print("[%s*%s] Stato: %s"%(bright_yellow,end, stat))
    if os.path.isfile("core/modules/output/tor_spoofed"):
        IP = ip()
        if IP == "-":
            try:
                IP = open("core/modules/output/tor_spoofed","r").read().split()[1]
            except IndexError:
                IP = "-"
        get_time = open("core/modules/output/tor_spoofed","r").read().split()[0]
        date = get_time.split("--")[0]
        time = get_time.split("--")[1]
        print("[%s+%s] Avviato      > %s (%s)"%(bright_green,end, time, date))
        if IP == "-":
            print("[%s!%s] Impossibile reperire l'indirizzo IP"%(red,end))
            print("  > Prova a riavviare Torghost")
        else:
            print("[%s*%s] Indirizzo IP > %s"%(bright_yellow,end, IP))

def writer():
    IP = ip()
    time = datetime.now().strftime('%d.%m.%Y--%H:%M:%S')
    os.system("echo '%s %s' > core/modules/output/tor_spoofed"%(time, IP))

def start_torghost():
    if TorrcCfgString in open(Torrc).read():
        print("[%s+%s] Torrc configurato"%(bright_green,end))
    else:
        with open(Torrc, "a") as myfile:
            sys.stdout.write("[%s*%s] Configuro Torrc           "%(bright_yellow,end))
            myfile.write(TorrcCfgString)
            sys.stdout.write("[%sOK%s]\n"%(bright_green,end))
            sys.stdout.flush()
    if resolvString in open(resolv).read():
        print("[%s+%s] DNS resolv.conf configurato"%(bright_green,end))
    else:
        with open(resolv, "w") as myfile:
            sys.stdout.write("[%s*%s] Configuro DNS resolv.conf "%(bright_yellow,end))
            myfile.write(resolvString)
            sys.stdout.write("[%sOK%s]\n"%(bright_green,end))
            sys.stdout.flush()
    sys.stdout.write("[%s*%s] Avvio il servizio Tor     "%(bright_yellow,end))
    os.system("service tor start")
    sys.stdout.write("[%sOK%s]\n"%(bright_green,end))
    sys.stdout.flush()
    sys.stdout.write("[%s*%s] Imposto regole iptables   "%(bright_yellow,end))
    iptables_rules = """
	NON_TOR="192.168.1.0/24 192.168.0.0/24"
	TOR_UID=%s
	TRANS_PORT="9040"
	iptables -F
	iptables -t nat -F
	iptables -t nat -A OUTPUT -m owner --uid-owner $TOR_UID -j RETURN
	iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports 53
	for NET in $NON_TOR 127.0.0.0/9 127.128.0.0/10; do
	 iptables -t nat -A OUTPUT -d $NET -j RETURN
	done
	iptables -t nat -A OUTPUT -p tcp --syn -j REDIRECT --to-ports $TRANS_PORT
	iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
	for NET in $NON_TOR 127.0.0.0/8; do
	 iptables -A OUTPUT -d $NET -j ACCEPT
	done
	iptables -A OUTPUT -m owner --uid-owner $TOR_UID -j ACCEPT
	iptables -A OUTPUT -j REJECT
	"""%(getoutput("id -ur debian-tor"))
    os.system(iptables_rules)
    sys.stdout.write("[%sOK%s]\n"%(bright_green,end))
    sys.stdout.flush()
    IP = ip()
    print("[#] Indirizzo IP: %s"%(IP))
    writer() # scrive quando attivo

def stop_torghost():
    print("[%s*%s] Fermo Torghost"%(bright_yellow,end))
    sys.stdout.write("[%s*%s] Ripristino configurazione iptables "%(bright_yellow,end))
    IpFlush = """
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT
    iptables -t nat -F
    iptables -t mangle -F
    iptables -F
    iptables -X
    """
    os.system(IpFlush)
    os.system("service network-manager restart")
    sys.stdout.write("[%sOK%s]\n"%(bright_green,end))
    sys.stdout.flush()
    IP = ip()
    print("[#] Indirizzo IP: %s"%(IP))
    if os.path.isfile("core/modules/output/tor_spoofed"):
        os.system("rm core/modules/output/tor_spoofed")

def switch_tor():
    sys.stdout.write("[%s*%s] Richiedo nuovo circuito "%(bright_yellow,end))
    try:
        with Controller.from_port(port = 9051) as controller:
            controller.authenticate()
            controller.signal(Signal.NEWNYM)
        sys.stdout.write("[%sOK%s]\n"%(bright_green,end))
        sys.stdout.flush()
        IP = ip()
        print("[%s*%s] Indirizzo IP: %s"%(bright_yellow,end, IP))
        writer()
    except:
        sys.stdout.write("[%sFail%s]\n"%(red,end))
        sys.stdout.flush()
        print("[%s-%s] Richiesta nuovo circuito fallita"%(red,end))
        final()

def control(arg):
    if arg == "start":
        start_torghost()
    elif arg == "stop":
    	stop_torghost()
    elif arg == "switch":
    	switch_tor()

def check(arg=None):
    check_spoof = CHECKSPOOF()
    if check_spoof == True:
        if arg == "startup":
            print("\n[%s+%s] Torghost Attivo"%(bright_green,end))
        else:
            print("[%s!%s] Torghost Attivo"%(red,end))
    else:
        pass
