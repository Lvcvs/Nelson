#!/usr/bin/python
# -*- coding: utf-8 -*-
import os
import sys
import json
import socks
import socket
import urllib2
import httplib
reload(sys)
sys.setdefaultencoding('utf8')

end = '\033[0m'
red = '\033[1;31m'
underline = '\033[4m'

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

def whois(target):
    socket.setdefaulttimeout(3)
    exist = True

    if "http://" in target: # codice di verifica
        target = target.replace("http://","")

    if "https://" in target: # codice di verifica
        target = target.replace("https://","")

    try:
        getip = socket.gethostbyname("%s"%(target))
    except socket.gaierror:
        print("[%s-%s] Indirizzo sconosciuto: %s"%(red,end, target))
        exist = False

    if exist == True:
        try: # codice di verifica
            response = urllib2.urlopen("http://ip-api.com/json/%s"%(getip))
        except (httplib.BadStatusLine,urllib2.URLError,socket.timeout):
            print("[%s-%s] Richiesta scaduta"%(red,end))
            final()
        except KeyboardInterrupt:
            print("\n[%s-%s] Interrotto\n"%(red,end))
            final()

        try: # preparativi
            data = response.read()
            values = json.loads(data)
            ip = getip
            socket.inet_aton(ip)
            hostname = socket.getfqdn(ip)
        except KeyboardInterrupt:
            print("\n[%s-%s] Interrotto\n"%(red,end))
            final()

        # informazioni relative a <indirizzo> in formato "leggibile"
        if hostname == ip:
            hostname = ""

        try:
            country = values['country']
        except KeyError:
            country = ""

        try:
            countrycode = values['countryCode']
            countrycode = "(%s)"%(countrycode)
        except KeyError:
            countrycode = ""

        try:
            region_name = values['regionName']
        except KeyError:
            region_name = ""

        try:
            region = values['region']
            region = "(%s)"%(region)
        except KeyError:
            region = ""

        try:
            city = values['city']
        except KeyError:
            city = ""

        try:
            zip_code = values['zip']
        except KeyError:
            zip_code = ""

        try:
            isp = values['isp']
        except KeyError:
            isp = ""

        try:
            org = values['org']
        except KeyError:
            org = ""

        try:
            gestore = values['as']
        except KeyError:
            gestore = ""

        try:
            lat_lon = str(values['lat']) + " / " + str(values['lon'])
        except KeyError:
            lat_lon = ""

        try:
            timezone = values['timezone']
        except KeyError:
            timezone = ""

        len_checker = [ip,hostname, str(country + " " + countrycode), str(region_name + " " + region), zip_code, city, isp, org, gestore, lat_lon, timezone]
        for e in len_checker:
            e = 14 * " " + str(e)
            check_len_message(e)

        # risultati
        print("")
        print("[#] %sWhois%s"%(underline,end))
        print(" IP        > %s "%(ip))
        print(" Hostname  > %s"%(hostname))
        print(" Nazione   > %s %s"%(country, countrycode))
        print(" Regione   > %s %s"%(region_name, region))
        print(" C.Postale > %s"%(zip_code))
        print(" Citta'    > %s"%(city))
        print(" Provider  > %s"%(isp))
        print(" Organizz. > %s"%(org))
        print(" Gestore   > %s"%(gestore))
        print(" Lat/Long  > %s"%(lat_lon))
        print(" F.Orario  > %s"%(timezone))
        print("")
