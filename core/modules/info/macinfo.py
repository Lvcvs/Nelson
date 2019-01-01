#!/usr/bin/python
# -*- coding: utf-8 -*-
import os
import sys
import json
import socket
import urllib2

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

def macinfo(mac):
    vendor = get_mac_vendor(mac)
    if vendor == "-":
        print("[%s-%s] Nessun risultato"%(red,end))
    else:
        print("[#] MAC > %s"%(mac))
        message = "[%s+%s]       %s"%(bright_green,end, vendor)
        check_len_message(message)
        print(message)
