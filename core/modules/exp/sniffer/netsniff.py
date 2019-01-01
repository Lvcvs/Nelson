#!/usr/bin/python
# -*- coding: utf-8 -*-
import os
import sys
import time
import logging
import netifaces
import multiprocessing
from scapy.all import sniff, wrpcap
from datetime import datetime
from core.modules.exp.sniffer import pcredz

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

end = '\033[0m'
red = '\033[1;31m'
bright_green = '\033[1;32m'
bright_yellow = '\033[1;33m'

def final():
    import nelson as n
    n.main()

Netsniff_Process = [] # processi netsniff

def stop(exit=False):
    netsniff_file = "core/modules/output/netsniff"
    pcapfile = "core/modules/exp/sniffer/output.pcap"
    logfile = "core/modules/exp/sniffer/Netsniff.log"

    # codice di verifica
    if exit == True:
        print("[%s*%s] Solo un momento"%(bright_yellow,end))
    if os.path.isfile("core/modules/output/netsniff") == False or len(Netsniff_Process) == 0:
        if exit == False:
            print("[%s-%s] Netsniff non attivo"%(red,end))
            final()

    for t in Netsniff_Process: # ferma processi
        t.terminate()
        Netsniff_Process.remove(t)

    if os.path.isfile(netsniff_file): # imposta netsniff come non attivo
        os.system("rm %s"%(netsniff_file))

    # estrazione contenuti output.pcap
    if exit == False:
        print("[%s*%s] Estraggo informazioni "%(bright_yellow,end))

    if os.path.isfile(pcapfile):
        if exit == True:
            pcredz.Run(pcapfile, exit=True)
        else:
            pcredz.Run(pcapfile)
        if os.path.isfile(logfile) == False: # copia file risultati
            try:
                time.sleep(3)
            except KeyboardInterrupt:
                print("\r  ")
        if os.path.isfile(logfile):
            os.system("cp %s core/output/ -r"%(logfile))

    # pulizia
    if os.path.isfile("core/modules/exp/sniffer/__init__.pyc"):
        os.system("rm core/modules/exp/sniffer/*.pyc")
    # informazioni finali
    ctime = datetime.now().strftime('%H:%M:%S')
    if exit == False:
        print("[%s+%s] Sessione salvata (core/output/Netsniff.log)"%(bright_green,end))
        print("[%s+%s] Netsniff fermato: %s"%(bright_green,end, ctime))
    else: # uscita nelson
        print("[%s!%s] Netsniff fermato: %s"%(red,end, ctime))

def start(iface):
    if os.path.isfile("core/modules/output/netsniff"): # codice di verifica
        if len(Netsniff_Process) == 0: # in caso di interruzione con ctrl z, questo riporta alla normalità
            stop(None,exit=True)
        else: # semplice verifica
            print("[%s-%s] Netsniff già attivo"%(red,end))
            final()

    if len(Netsniff_Process) != 0:
        print("[%s-%s] Netsniff in funzione"%(red,end))
        final()

    pcapfile = os.getcwd() + "/core/modules/exp/sniffer/output.pcap"

    if os.path.isfile(pcapfile):
        os.system("rm %s"%(pcapfile))
    if os.path.isfile(pcapfile) == False:
        os.system("touch %s"%(pcapfile))

    # sniffer
    def sniffer():
        def write(pkt):
            pcapfile = os.getcwd() + "/core/modules/exp/sniffer/output.pcap"
            sys.stdout = wrpcap(pcapfile, pkt, append=True)

        sys.stderr = open(os.devnull, "w")
        pkt = sniff(iface, prn=write, filter="tcp", store=1)

    t = multiprocessing.Process(target=sniffer) # avvia il processo in background
    Netsniff_Process.append(t) # aggiunge il processo in lista
    t.start()

    netsniff_file = "core/modules/output/netsniff"

    stime = datetime.now().strftime('%d.%m.%Y--%H:%M:%S')
    os.system("echo '%s %s' > %s"%(stime,iface, netsniff_file)) # ora di avvio
    time = datetime.now().strftime('%H:%M:%S') # ora di avvio "leggibile"

    print("[%s+%s] Netsniff avviato: %s"%(bright_green,end, time))


def status():
    def CHECKACTIVE(): # codice di verifica
        if os.path.isfile("core/modules/output/netsniff"):
            return True
        else:
            return False

    if CHECKACTIVE() == True: # codice di verifica
        stat = bright_green+"Attivo"+end
    else:
        stat = red+"Non Attivo"+end


    print("[#] Netsniff")
    print("[%s*%s] Stato: %s"%(bright_yellow,end, stat))


    if os.path.isfile("core/modules/output/netsniff"): # informazioni relative a netsniff
        openfile = open("core/modules/output/netsniff","r").read().split()
        get_time = openfile[0]
        date = get_time.split("--")[0]
        time = get_time.split("--")[1]
        used_iface = openfile[1]
        print("[%s+%s] Avviato     > %s (%s)"%(bright_green,end, time,date))
        print("[%s*%s] Interfaccia > %s"%(bright_yellow,end, used_iface))

def extract():
    netsniff_file = "core/modules/output/netsniff"
    logfile = "core/output/Netsniff.log"
    father_logfile = "core/modules/exp/sniffer/Netsniff.log"

    if os.path.isfile(netsniff_file):
        print("[%s-%s] Netsniff attivo"%(red,end))
        final()

    exist = False

    if os.path.isfile(father_logfile):
        cat = open(father_logfile,"r").read()
        if len(cat) != 0:
            print(cat)
            exist = True

    if exist == False:
        print("[%s-%s] Nessuna informazione"%(red,end))



def clearlogs():
    logfile = "core/output/Netsniff.log"
    father_logfile = "core/modules/exp/sniffer/Netsniff.log"

    cleaned = False
    if os.path.isfile(father_logfile):
        os.system("rm %s"%(father_logfile))
        cleaned = True

    if os.path.isfile(logfile):
        os.system("rm %s"%(logfile))
        cleaned = True

    if cleaned == False:
        print("[%s-%s] Nessun file da pulire"%(red,end))
    else:
        print("[%s+%s] Pulizia completata"%(bright_green,end))


def control(args, iface): # controllo script
    if args == "start":
        start(iface)

    if args == "status":
        status()

    if args == "stop":
        stop()

    if args == "NelsonExit":
        stop(exit=True)

    if args == "extract":
        extract()

    if args == "clearlogs":
        clearlogs()
