#!/usr/bin/python
# -*- coding: utf-8 -*-
import os
import re
import sys
import uuid
import socket
import requests
import netifaces

reload(sys)
sys.setdefaultencoding('utf8')

end = '\033[0m'
red = '\033[1;31m'
underline = '\033[4m'
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

def get_gateway(): # gateway
    try:
        val = []
        gateway = netifaces.gateways()[2]
        for i in gateway:
            for e in i:
                val.append(e)
        gateway = val[0]
    except KeyError:
        gateway = "-"
    return gateway

def netinfo(iface, args):
    try:
        localip = [l for l in ([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][:1], [[(s.connect(('8.8.8.8', 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) if l][0][0]
    except (socket.herror,socket.gaierror):
        localip = netifaces.ifaddresses(str(iface))[netifaces.AF_INET][0]['addr']
    except socket.error:
        localip = "-"

    try:
        publicip = requests.get('http://ip.42.pl/raw', timeout=3).text
    except requests.exceptions.ConnectionError:
        publicip = "-"
    except KeyboardInterrupt:
        print("\n[%s-%s] Interrotto\n"%(red,end))
        final()

    mac_permanent = ':'.join(re.findall('..', '%012x' % uuid.getnode()))
    print("")

    # connessioni stabilite
    established = "netstat -atu | grep 'ESTABLISHED'"

    try:
        if "-n" in args: # in caso di argomenti
            established = "netstat -natu | grep 'ESTABLISHED'"
    except TypeError:
        pass

    try:
        if "-a" in args:
            established = "netstat -epatu | grep 'ESTABLISHED'"
    except TypeError:
        pass

    try:
        if "-n" in args and "-a" in args:
            established = "netstat -epnatu | grep 'ESTABLISHED'"
    except TypeError:
        pass

    try:
        results = os.popen(established).read().splitlines()
    except KeyboardInterrupt:
        print("  \r[%s-%s] Interrotto\n"%(red,end))
        final()

    processing = []

    for e in results:
        e = e.replace("ESTABLISHED","")
        e = e.split()
        processing.append(e)

    print("[#] %sConnessioni stabilite%s"%(underline,end))

    try:
        if "-a" in args:
            print("\n[#] Visualizzazione: <connessioni:%sporte%s> -# %sutente%s > %sPID%s/%sProcesso%s"%(bright_green,end, bright_yellow,end, red,end, red,end))
    except TypeError:
        pass

    if len(processing) == 0:
        print("\n[%s-%s] Nessun risultato"%(red,end))
    else:
        tcp = []
        udp = []
        tcp6 = []
        udp6 = []

        for e in processing:
            type = e[0]
            if type == "tcp":
                tcp.append(e)
            if type == "udp":
                udp.append(e)
            if type == "tcp6":
                tcp6.append(e)
            if type == "udp6":
                udp6.append(e)

        # ordina le liste
        tcp.sort()
        udp.sort()
        tcp6.sort()
        udp6.sort()

        if len(tcp) != 0:
            print("\n  > TCP")

            for e in tcp:
                srce, srce_port = e[3].split(":")[0], str(":" + bright_green + e[3].split(":")[1] + end)
                dest, dest_port = e[4].split(":")[0], str(":" + bright_green + e[4].split(":")[1] + end)
                try:
                    if "-a" in args:
                        user = str(bright_yellow + e[5] + end)

                        pid, proc = e[7].split("/"), e[7]#str(red + e[7].split("/")[0]) + end, str("/" + red + e[7].split("/")[1] + end)

                        if "/" in e[7]: # elimina l'eccezione IndexError
                            if len(pid) != 3: # evita errori di output
                                pid, proc = str(red + e[7].split("/")[0]) + end, str("/" + red + e[7].split("/")[1] + end)
                            else:
                                pid, proc = str(red + e[7].split("/")[0]) + end, str("/" + red + e[7].split("/")[2] + end)

                        else:
                            pid, proc = "-/", "-"

                        message = "    %s > %s -# %s > %s"%(srce+srce_port, dest+dest_port, user, pid+proc)
                    else:
                        message = "    %s > %s"%(srce+srce_port, dest+dest_port)
                except TypeError:
                    message = "    %s > %s"%(srce+srce_port, dest+dest_port)

                check_len_message(message)
                print(message)


        if len(udp) != 0:
            print("\n  > UDP")

            for e in udp:
                srce, srce_port = e[3].split(":")[0], str(":" + bright_green + e[3].split(":")[1] + end)
                dest, dest_port = e[4].split(":")[0], str(":" + bright_green + e[4].split(":")[1] + end)
                try:
                    if "-a" in args:
                        user = str(bright_yellow + e[5] + end)

                        if "/" in e[7]: # elimina l'eccezione IndexError
                            pid, proc = str(red + e[7].split("/")[0]) + end, str("/" + red + e[7].split("/")[1] + end)
                        else:
                            pid, proc = "-/", "-"

                        message = "    %s > %s -# %s > %s"%(srce+srce_port, dest+dest_port, user, pid+proc)
                    else:
                        message = "    %s > %s"%(srce+srce_port, dest+dest_port)
                except TypeError:
                    message = "    %s > %s"%(srce+srce_port, dest+dest_port)

                check_len_message(message)
                print(message)


        if len(tcp6) != 0:
            print("\n  > TCP6")

            for e in tcp6:
                # questo serve per evitare errori con l'output colorato,
                # i colori vanno aggiunti successivamente
                srce_port = e[3].split(":")[-1]
                dest_port = e[3].split(":")[-1]

                srce = e[3].replace(srce_port, "")
                dest = e[4].replace(dest_port, "")

                srce, srce_port = srce, bright_green + srce_port + end
                dest, dest_port = dest, bright_green + dest_port + end

                ipv6 = False

                try:
                    if len(dest.split(":")) == 2: # ipv4
                        dest, dest_port = str(dest.split(":")[0]), ":" + bright_green + str(dest.split(":")[1]) + end
                        message = "    %s > %s"%(srce+srce_port, dest+dest_port)
                    else: # ipv6
                        ipv6 = True
                        message = "    %s > %s"%(srce+srce_port, dest)
                except IndexError:
                    pass

                try:
                    if "-a" in args:
                        user = str(bright_yellow + e[5] + end)

                        if "/" in e[7]: # elimina l'eccezione IndexError
                            pid, proc = str(red + e[7].split("/")[0]) + end, str("/" + red + e[7].split("/")[1] + end)
                        else:
                            pid, proc = "-/", "-"

                        message = "    %s > %s -# %s > %s"%(srce+srce_port, dest+dest_port, user, pid+proc)
                    else:
                        if ipv6 == True:
                            message = "    %s > %s"%(srce+srce_port, dest)
                        else:
                            message = "    %s > %s"%(srce+srce_port, dest+dest_port)

                except TypeError:
                    if ipv6 == True:
                        message = "    %s > %s"%(srce+srce_port, dest)
                    else:
                        message = "    %s > %s"%(srce+srce_port, dest+dest_port)

                check_len_message(message)
                print(message)


        if len(udp6) != 0:
            print("\n  > UDP6")

            for e in udp6:
                # questo serve per evitare errori con l'output colorato,
                # i colori vanno aggiunti successivamente
                srce_port = e[3].split(":")[-1]
                dest_port = e[3].split(":")[-1]

                srce = e[3].replace(srce_port, "")
                dest = e[4].replace(dest_port, "")

                srce, srce_port = srce, bright_green + srce_port + end
                dest, dest_port = dest, bright_green + dest_port + end

                ipv6 = False

                try:
                    if len(dest.split(":")) == 2: # ipv4
                        dest, dest_port = str(dest.split(":")[0]), ":" + bright_green + str(dest.split(":")[1]) + end
                        message = "    %s > %s"%(srce+srce_port, dest+dest_port)
                    else: # ipv6
                        ipv6 = True
                        message = "    %s > %s"%(srce+srce_port, dest)
                except IndexError:
                    pass

                try:
                    if "-a" in args:
                        user = str(bright_yellow + e[5] + end)

                        if "/" in e[7]: # elimina l'eccezione IndexError
                            pid, proc = str(red + e[7].split("/")[0]) + end, str("/" + red + e[7].split("/")[1] + end)
                        else:
                            pid, proc = "-/", "-"

                        message = "    %s > %s -# %s > %s"%(srce+srce_port, dest+dest_port, user, pid+proc)
                    else:
                        if ipv6 == True:
                            message = "    %s > %s"%(srce+srce_port, dest)
                        else:
                            message = "    %s > %s"%(srce+srce_port, dest+dest_port)

                except TypeError:
                    if ipv6 == True:
                        message = "    %s > %s"%(srce+srce_port, dest)
                    else:
                        message = "    %s > %s"%(srce+srce_port, dest+dest_port)

                check_len_message(message)
                print(message)

    # hostname
    l_host = socket.gethostname() # Exceptions?
    try:
        p_host = socket.gethostbyaddr(publicip)[0]
    except (socket.herror,socket.gaierror):
        p_host = socket.getfqdn(publicip)
    except KeyboardInterrupt:
        p_host = "-"

    # codice di verifica
    if l_host == localip:
        l_host = "-"
    if p_host == publicip:
        p_host = "-"

    check_len_message(" Hostname Locale   > %s"%(l_host))
    check_len_message(" Hostname Pubblico > %s"%(p_host))

    # risultato
    print("\n")
    print("[#] %sInformazioni di rete%s"%(underline,end))
    print(" Interfaccia       > %s"%(iface))
    print(" MAC               > %s"%(mac_permanent.upper()))
    print(" Gateway           > %s"%(str(get_gateway())))
    print(" IP Locale         > %s"%(localip))
    print(" IP Pubblico       > %s"%(publicip))
    print(" Hostname Locale   > %s"%(l_host))
    print(" Hostname Pubblico > %s\n"%(p_host))
