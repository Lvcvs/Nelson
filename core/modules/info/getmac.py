#!/usr/bin/python
# -*- coding: utf-8 -*-
import urllib2,json,socket # vendor's mac
import os
import re
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

def getmac(ip):
    print("\n[#] Getmac\n")
    print("[#] %s"%(ip))
    DEVNULL = open(os.devnull, "wb") # nessun output

    if "http://" in ip: # codice di verifica
        ip = ip.replace("http://","")
    if "https://" in ip: # codice di verifica
        ip = ip.replace("https://","")

    pid = Popen(["arp", "-n", ip], stdout=PIPE, stderr=DEVNULL) # ottiene indirizzo mac
    s = pid.communicate()[0]

    exist = True
    try:
        mac = re.search(r"(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})", s).groups()[0] # ottiene indirizzo mac
    except AttributeError:
        print("[%s-%s] Nessun risultato\n"%(red,end))
        exist = False

    if exist == True:
        print("[%s+%s] %s"%(bright_green,end, mac))
        vendor = get_mac_vendor(mac)

        if vendor != None:
            message = "[%s+%s] %s"%(bright_green,end, vendor)
            check_len_message(message)
            print(message + "\n")
        else:
            print("")
