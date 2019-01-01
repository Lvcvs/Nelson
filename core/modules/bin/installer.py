#!/usr/bin/python
# -*- coding: utf-8 -*-
import os
import sys
import urllib2

end = '\033[0m'
red = '\033[1;31m'
bright_green = '\033[1;32m'
bright_yellow = '\033[1;33m'

def final():
    import nelson as n
    n.main()

def check_conn(reinstall=False):
    try:
        urllib2.urlopen('https://www.google.com')
    except (urllib2.URLError,KeyboardInterrupt):
        print("[%s-%s] Internet non disponibile, verifica la connessione e riprova"%(red,end))
        if reinstall == True:
            final()
        else:
            exit()

def CreateListsDir():
    if os.path.isdir("core/modules/lists") == False:
        os.system("mkdir core/modules/lists")
    if os.path.isfile("core/modules/lists/whitelist.txt") == False:
        os.system("touch core/modules/lists/whitelist.txt")
    if os.path.isfile("core/modules/lists/blacklist.txt") == False:
        os.system("touch core/modules/lists/blacklist.txt")

def install():
    check_conn()
    print("\n[%s*%s] Installo pacchetti\n"%(bright_yellow,end))
    os.system("apt purge python-pypcap -y")
    os.system("apt install python-pip tor rfkill python-libpcap network-manager -y")
    os.system("pip install --upgrade pip")
    print("\n[%s*%s] Installo librerie\n"%(bright_yellow,end))
    os.system("pip install netifaces requests pybluez python-nmap stem rarfile")
    if os.path.isdir("core/output") == False:
        os.system("mkdir core/output")
    if os.path.isdir("core/modules/output") == False:
        os.system("mkdir core/modules/output")
    if os.path.isdir("core/modules/lists") == False:
        os.system("mkdir core/modules/lists")
    os.system("touch /usr/local/sbin/nelson && echo 'cd %s/ && python nelson.py' > /usr/local/sbin/nelson && chmod +x /usr/local/sbin/nelson"%(os.getcwd()))
    os.system("chmod +x nelson.py")
    os.system("touch core/modules/output/installed")
    print("\n[%s!%s] Spostando la cartella di Nelson non sarà più disponibile il\n    comando di avvio rapido. Usa il comando '$ reinstall' dal\n    programma per sistemare il problema.\n"%(bright_yellow,end))
    print("[%s+%s] Installazione completata"%(bright_green,end))
    print("[%s+%s] Puoi avviare il programma digitando '$ nelson' ovunque\n"%(bright_green,end))
    sys.exit()

def reinstall():
    check_conn(reinstall=True)
    print("\n[%s*%s] Reinstallo pacchetti\n"%(bright_yellow,end))
    os.system("apt purge python-pypcap -y")
    os.system("apt install python-pip tor python-libpcap -y")
    print("\n[%s*%s] Reinstallo librerie\n"%(bright_yellow,end))
    os.system("pip install netifaces requests pybluez python-nmap stem")
    if os.path.isdir("core/output") == False:
        os.system("mkdir core/output")
    if os.path.isdir("core/modules/output") == False:
        os.system("mkdir core/modules/output")
    if os.path.isdir("core/modules/lists") == False:
        os.system("mkdir core/modules/lists")
    os.system("touch /usr/local/sbin/nelson && echo 'cd %s/ && python nelson.py' > /usr/local/sbin/nelson && chmod +x /usr/local/sbin/nelson"%(os.getcwd()))
    os.system("chmod +x nelson.py")
    os.system("touch core/modules/output/installed")
    print("\n[%s+%s] Avvio rapido aggiornato"%(bright_green,end))
    print("[%s+%s] Reinstallazione completata\n"%(bright_green,end))

def uninstall():
    if os.path.isfile("/usr/local/sbin/nelson"):
        os.system("rm /usr/local/sbin/nelson")
    if os.path.isdir("../Nelson"):
        os.system("cd .. && rm Nelson/ -r")
    print("\n[%s+%s] Disinstallazione Completata\n"%(bright_green,end))
    sys.exit()
