#!/usr/bin/python
# -*- coding: utf-8 -*-
import os
import re
import sys
import time
import socket
import netifaces
import subprocess
import multiprocessing
import urllib2,json # vendor
from datetime import datetime
from subprocess import Popen, PIPE

end = '\033[0m'
red = '\033[1;31m'
bright_green = '\033[1;32m'
bright_yellow = '\033[1;33m'

def final():
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

def pinger(job_q, results_q): # verifica se connesso
    DEVNULL = open(os.devnull, 'w')
    while True:
        ip = job_q.get()
        if ip is None:
            break
        try:
            subprocess.check_call(['ping', '-c1', ip], stdout=DEVNULL, stderr=DEVNULL)
            results_q.put(ip)
        except:
            pass

def get_my_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        s.connect(("8.8.8.8", 80))
    except socket.error:
        print("\n[%s-%s] Nessuna connessione\n"%(red,end))
        final()

    ip = s.getsockname()[0]
    s.close()
    return ip

def get_mac_vendor(mac):
    socket.setdefaulttimeout(1)
    vendor = "-"
    try:
        response = urllib2.urlopen("http://macvendors.co/api/%s"%(mac))
        data = response.read()
        values = json.loads(data)
        vendor = values['result']['company']
    except:
        pass

    return vendor

def progress(count, total): # percentuale di caricamento
    percents = round(100.0 * count / float(total), 1)
    sys.stdout.write('{}% '.format(percents))
    sys.stdout.flush()

def map_network(pool_size=255):
    ip_list = list()
    ip_parts = get_my_ip().split('.')
    base_ip = ip_parts[0] + '.' + ip_parts[1] + '.' + ip_parts[2] + '.'
    jobs = multiprocessing.Queue()
    results = multiprocessing.Queue()
    pool = [multiprocessing.Process(target=pinger, args=(jobs, results)) for i in range(pool_size)]

    for p in pool:
        p.start()

    for i in range(1, 256):
        jobs.put(base_ip + '{0}'.format(i))

    for p in pool:
        jobs.put(None)

    try:
        analyzed = 0
        s_time = datetime.now().strftime('%H:%M:%S')
        print("\n[%s+%s] Scansione di rete avviata: %s"%(bright_green,end, s_time))

        for p in pool:
            sys.stdout.write("\r[%s*%s] Progresso: "%(bright_yellow,end))
            analyzed += 1
            progress(analyzed, total=255)
            sys.stdout.flush()
            p.join()

    except KeyboardInterrupt:
        print("\n[%s-%s] Interrotto\n"%(red,end))
        final()

    while not results.empty():
        ip = results.get()
        ip_list.append(ip)

    print("\n")
    return ip_list

def scan(iface, port_scan, fast_portscan):
    try:
        localip = [l for l in ([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][:1], [[(s.connect(('8.8.8.8', 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) if l][0][0]
    except (socket.herror,socket.gaierror):
        localip = netifaces.ifaddresses(str(iface))[netifaces.AF_INET][0]['addr']

    start_ = time.time()

    ip_split = localip.split(".")

    print("\n[#] Netscan\n")

    if port_scan == True:
        print("[#] Tipo: dispositivi + porte")

        if fast_portscan == True:
            print("[#] Scansione porte: rapida")
        else:
            print("[#] Scansione porte: normale")
    else:
        print("[#] Tipo: solo dispositivi")
    print("[#] Raggio: %s"%(ip_split[0] + "." + ip_split[1] + "." + ip_split[2] + ".1-255"))

    try:
        lst = map_network()
    except KeyboardInterrupt:
        print("\n[%s-%s] Interrotto\n"%(red,end))
        final()

    devices = []
    for dev in lst:
        devices.append(dev)

    devices = sorted(devices, key=lambda x:map(int, x.split('.'))) # ordina indirizzi ip

    for ip in devices:
        syntax = "%s+%s"%(bright_green,end)
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            if hostname == ip:
                syntax = "%s-%s"%(red,end)
                hostname = "-"
        except socket.herror:
            hostname = socket.getfqdn(ip)
            if hostname == ip:
                syntax = "%s-%s"%(red,end)
                hostname = "-"

        pid = Popen(["arp", "-n", ip], stdout=PIPE)
        s = pid.communicate()[0]

        try: # ottenimento indirizzo mac
            mac = re.search(r"(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})", s).groups()[0]
        except AttributeError:
            ip += " # Locale"
            mac = os.popen("ethtool -P %s"%(iface)).read().split()[2]

        vendor = get_mac_vendor(mac)

        if vendor == "-":
            syntax_vendor = "%s-%s"%(red,end)
        if vendor != "-":
            syntax_vendor = "%s+%s"%(bright_green,end)

        print("[#] IP       -# %s"%(ip))
        print("[%s+%s] MAC      -# %s"%(bright_green,end, mac.upper())) # mac.upper > lettere maiuscole

        msgs = ["[%s] Vendor   -# %s"%(syntax_vendor, vendor), "[%s] Hostname -# %s"%(syntax, hostname)]
        for message in msgs:
            check_len_message(message)
            print(message)

        if port_scan == True: # -p / --portscan
            from core.modules.scanning import portscan
            if fast_portscan == True: # scansione rapida
                scan = portscan.portscan(ip,arg="netscan",fast_scan=True)
            else:
                scan = portscan.portscan(ip,arg="netscan")
        else:
            print("")

    # "blacklisted"
    read_blacklist = open("core/modules/lists/blacklist.txt","r").readlines()

    if len(read_blacklist) != 0:
        blacklist = []
        blackwarn = []

        for e in read_blacklist: # legge e salva i disp. in blacklist
            if "\n" in e:
                e = e.replace("\n","")
            blacklist.append(e)

        for dev in devices: # riconosce se disp. in blacklist è connesso
            if dev in blacklist:
                blackwarn.append(dev)

        if len(blackwarn) != 0: #
            if len(blackwarn) != 1: # codice di verifica
                syntax = "i"
            else:
                syntax = "o"
            print("[%s!%s] Dispositiv%s in blacklist conness%s\n"%(red,end, syntax,syntax))
            for dev in blackwarn:
                try: # ottiene l'hostname
                    hostname = socket.gethostbyaddr(dev)[0]
                except socket.herror:
                    hostname = socket.getfqdn(dev)
                    if hostname == dev:
                        hostname = ""
                print("[%s-%s] %s"%(red,end, dev))
                if hostname == "":
                    pass
                else:
                    print("[%s-%s] Hostname > %s"%(red,end, hostname))
            print("")

    # end
    end_ = time.time()
    elapsed = round((end_-start_), 2)
    e_time = datetime.now().strftime('%H:%M:%S')
    print("[%s+%s] Terminata > %s"%(bright_green,end, e_time))
    print("[%s+%s] Connessi  > %s"%(bright_green,end, len(devices)))
    print("[%s*%s] Durata    > %s secondi\n"%(bright_yellow,end, elapsed))
