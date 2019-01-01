#!/usr/bin/python
# -*- coding: utf-8 -*-
import os
import sys
import time
import socket
import signal
import platform
from datetime import datetime

reload(sys)
sys.setdefaultencoding('utf8')

end = '\033[0m'
red = '\033[1;31m'
bright_green = '\033[1;32m'
bright_yellow = '\033[1;33m'

from core.modules.bin import installer as i
def installer(arg=None):
    if arg == "listsdir":
        i.CreateListsDir()
    else:
        i.install()

def IsNethunter():
    if os.path.isdir("/sdcard"):
        return True
    else:
        return False

# Printers
def printerr(text):
    print("[%s-%s] %s"%(red,end,text))
def printinf(text):
    print("[%s*%s] %s"%(bright_yellow,end,text))
def printpls(text):
    print("[%s+%s] %s"%(bright_green,end,text))

def check_sys(): # Verifica compatibilità sistemi
    systems = ["Kali","Parrot"]
    system = platform.linux_distribution()[0]
    if system not in systems:
        print("")
        printerr("Programma non compatibile col tuo sistema\n")
        sys.exit()
try:
    import netifaces,requests,readline
except ImportError:
    check_sys()
    installer()

def handler(signum, frame): # ctrl+z handler
    print(" > Ctrl+Z rilevato, arresto forzato")
signal.signal(signal.SIGTSTP, handler)

# bin
def helpers(type, arg=None): # messaggi di aiuto
    from core.modules.bin import helper
    if type == "logo":
        if arg == "logo_msg":
            helper.logo_msg()
        else:
            helper.logo()

    if type == "cmd":
        helper.cmd_help()

    if type == "edit":
        helper.edit_help()

    if type == "netsniff":
        helper.netsniff_help()

    if type == "crackle":
        helper.crackle_help()


def edit_menu():
    from core.modules.lists import edit
    edit.control()

# scanning
def netscan(iface, port_scan, fast_portscan):
    from core.modules.scanning import netscan
    netscan.scan(iface, port_scan, fast_portscan)

def portscan(ip,arg=None,target_num=0,fast_scan=False):
    from core.modules.scanning import portscan
    portscan.portscan(ip,arg,target_num,fast_scan)

def bluescan():
    from core.modules.scanning import bluescan
    bluescan.scan()

def cpscan(targets):
    from core.modules.scanning import cpscan
    cpscan.main(targets)

# info
def whois(target):
    from core.modules.info import whois
    whois.whois(target)

def netinfo(iface, args=None):
    from core.modules.info import netinfo
    netinfo.netinfo(iface, args)

def trace(target):
    from core.modules.info import trace
    trace.trace(target)

def getmac(ip):
    from core.modules.info import getmac
    getmac.getmac(ip)

def gethost(target):
    from core.modules.info import gethost
    gethost.gethost(target)

def macinfo(mac):
    from core.modules.info import macinfo
    macinfo.macinfo(mac)

# exp
def nuker(target,threads,limit_pkg,port):
    from core.modules.exp import nuker
    nuker.nuker(target,threads,limit_pkg,port)

def wakeup(ip, mac):
    from core.modules.exp import wol
    wol.wakeup(ip, mac)

def netsniff(arg, iface):
    from core.modules.exp.sniffer import netsniff
    netsniff.control(arg, iface)

def jtnuke(target, packets, message):
    from core.modules.exp import jtnuke
    jtnuke.start(target, packets, message)

def crackle(argument, crackobj, choice):
    from core.modules.exp import crackle
    if argument == "hash_check":
        crackle.hash_checker("check",crackobj)
    if argument == "hash_identify":
        crackle.hash_checker("identify",crackobj)
    if argument == "hash_check_silently":
        check = crackle.hash_checker("check_silently",crackobj)
        return check
    if argument == "hash_crack":
        crackle.hash_crack(crackobj, choice)
    if argument == "zip_crack":
        crackle.zipper_crack(crackobj, choice)
    if argument == "rar_crack":
        crackle.zipper_crack(crackobj, choice)

# spoofing
def macspoof(iface, mode, arg=None):
    from core.modules.spoofing import macspoof
    if mode == "spoof":
        macspoof.spoof(iface)
    if mode == "unspoof":
        macspoof.unspoof(iface)
    if mode == "check":
        if arg == "startup":
            macspoof.check(arg)
        else:
            macspoof.check()
    if mode == "status":
        macspoof.status()

def torghost(mode, arg=None, arg2=None):
    from core.modules.spoofing import torghost
    if arg == "check":
        if arg2 == "startup":
            torghost.check("startup")
        else:
            torghost.check()
    if arg == "status":
        torghost.status()
    else:
        torghost.control(mode)

#####
def N_Exit():
    print("\r  ")
    torghost(None, "check")
    macspoof(None, "check")

    if os.path.isfile("core/modules/output/netsniff"): # verifica se attivo netsniff
        netsniff("NelsonExit", None)
    # pulizia generale
    if os.path.isfile("nelson.pyc"):
        os.system("rm *.pyc")
    if os.path.isfile("core/modules/__init__.pyc"):
        if os.path.isfile("core/__init__.pyc"):
            os.system("rm core/*.pyc")
        if os.path.isfile("core/modules/__init__.pyc"):
            os.system("rm core/modules/*.pyc")
        if os.path.isfile("core/modules/bin/__init__.pyc"):
            os.system("rm core/modules/bin/*.pyc")
        if os.path.isfile("core/modules/exp/__init__.pyc"):
            os.system("rm core/modules/exp/*.pyc")
        if os.path.isfile("core/modules/exp/sniffer/__init__.pyc"):
            os.system("rm core/modules/exp/sniffer/*.pyc")
        if os.path.isfile("core/modules/info/__init__.pyc"):
            os.system("rm core/modules/info/*.pyc")
        if os.path.isfile("core/modules/lists/__init__.pyc"):
            os.system("rm core/modules/lists/*.pyc")
        if os.path.isfile("core/modules/scanning/__init__.pyc"):
            os.system("rm core/modules/scanning/*.pyc")
        if os.path.isfile("core/modules/spoofing/__init__.pyc"):
            os.system("rm core/modules/spoofing/*.pyc")
    print("[#] Uscita effettuata\n")
    sys.stdout.write("\x1B]0;\x07") # titolo terminale normale
    exit()

def check_conn(silent=False): # Verifica la connessione
    iface = "-"
    try:
        iface = netifaces.gateways()['default'][netifaces.AF_INET][1]
    except KeyError:
        try: # compatibilità nethunter
            values = []
            get_iface = netifaces.gateways()[2]

            for val in get_iface:
                for e in val:
                    values.append(e)

            iface = str(values[1])
        except KeyError:
            if silent != False:
                pass
            else:
                printerr("Nessuna connessione")
                main()
        except KeyboardInterrupt:
            print("")
            printerr("Interrotto")
            main()
    except KeyboardInterrupt:
        print("")
        printerr("Interrotto")
        main()
    return iface

def main():
    from core.modules.bin import completer # tab
    completer.normal()

    if IsNethunter() == True:
        bash = "[#]-[ %sNethunter%s ]-[ %sNelson%s ]\n[$] > "%(bright_green,end, bright_green,end)
    else:
        bash = "\r"+u"\u250C"+3*u"\u2500"+"[ %sroot@%s ]"%(bright_green,os.getlogin()+end)+u"\u2500"+"[ %sNelson%s ]\n"%(bright_green,end)+u"\u2514"+u"\u2500"+u"\u257C"+" # "

    try:
        cmd_input = raw_input(bash)
    except (KeyboardInterrupt,RuntimeError):
        try:
            print(" > Premi nuovamente Ctrl+C per uscire")
            time.sleep(.6)
            main()
        except KeyboardInterrupt:
            N_Exit()
    except EOFError:
        printerr("Usa 'quit','exit' o 'Ctrl+C' per uscire")
        main()

    tokens = cmd_input.split()

    try:
        command = tokens[0]
    except IndexError:
        command = None

    try:
        option = tokens[1]
    except IndexError:
        option = None

    try:
        argument = tokens[2]
    except IndexError:
        argument = None

##### SHELL
    accepted = [
    "ls","pwd","cat","cp","echo","touch","ps","kill","clear","reset","apt",
    "service","ftp","ssh","ifconfig","hciconfig","ip","ping"
    ]
    if command in accepted:
        print("  > $ %s"%(cmd_input))
        os.system(cmd_input)
        main()

##### CORE
    if command == "help" or command == "?":
        helpers("cmd")
        main()

    elif command == "os":
        if option:
            cmd_input = cmd_input.replace("os ","")
            print("  > $ %s"%(cmd_input))
            os.system(cmd_input)
        else:
            print("  > $ os <comando>")
        main()

    elif command == "edit":
        edit_menu()

    elif command == "status":
        if os.path.isfile("core/modules/lists/whitelist.txt"):
            print("\n[#] Whitelist")
            show = open("core/modules/lists/whitelist.txt","r").read().splitlines()
            if len(show) == 0:
                printerr("Nessun elemento")
            else:
                for e in show:
                    printpls("%s"%(e))
        if os.path.isfile("core/modules/lists/blacklist.txt"):
            print("\n[#] Blacklist")
            show = open("core/modules/lists/blacklist.txt","r").read().splitlines()
            if len(show) == 0:
                printerr("Nessun elemento")
            else:
                for e in show:
                    printpls("%s"%(e))
        print("")
        netsniff("status", iface=check_conn(silent=True))
        print("")
        macspoof(None, "status")
        print("")
        torghost(None, "status")
        print("")
        main()

    elif command == "banner":
        helpers("logo")
        print("")
        main()

    elif command == "reinstall":
        from core.modules.bin import installer
        installer.reinstall()
        main()

    elif command == "uninstall":
        if option:
            if option == "--yes":
                from core.modules.bin import installer
                installer.uninstall()
            else:
                printerr("Usa 'uninstall --yes' per disinstallare Nelson")
        else:
            print("\n[#] Nelson verrà rimosso completamente dal tuo sistema")
            print("[#] Potrai scaricarlo nuovamente dal seguente link:")
            print("    https://www.github.com/Skull00/Nelson")
            print("[#] Esegui il comando 'uninstall --yes' per procedere\n")
        main()

    elif command == "quit" or command == "exit":
        N_Exit()

##### INFO
    elif command == "gethost":
        if option:
            check_conn()
            targets = cmd_input.replace("gethost ","").split()
            print("\n[#] Gethost\n")
            for e in targets:
                gethost(e)
        else:
            print("  > $ gethost <IP/url> [IP2/url2] [IP3/url3] ...")
        main()

    elif command == "getmac":
        if option:
            check_conn()
            targets = cmd_input.replace("getmac ","").split()
            for e in targets:
                getmac(e)
        else:
            print("  > $ getmac <target> [target2] [target3] ...")
        main()

    elif command == "netinfo":
        iface = check_conn()
        if option:
            valid_args = ["-n","-a","-an","-na"]
            args = cmd_input.split()[1:]
            for e in args:
                if e in valid_args:
                    pass
                else:
                    printerr("Argomento '%s' non valido"%(e))
                    main()
            netinfo(iface, args)
        else:
            netinfo(iface)
        main()

    elif command == "trace":
        if option:
            check_conn()
            trace(option)
        else:
            print("  > $ trace <target>")
        main()

    elif command == "whois":
        if option:
            check_conn()
            rpl = cmd_input.replace("whois ","").split()
            for e in rpl:
                whois(e)
        else:
            print("  > $ whois <target> [target2] [target3] ...")
        main()

    elif command == "macinfo":
        if option:
            if len(option) != 17:
                printerr("Indirizzo MAC non valido")
            else:
                for e in cmd_input.split():
                    if "macinfo" in e:
                        pass
                    else:
                        print("")
                        macinfo(option)
                print("")
        else:
            print("  > $ macinfo <MAC> [MAC2] [MAC3] ...")
        main()

##### SCANNING
    elif command == "cpscan":
        if option:
            check_conn()
            targets = []
            get_targets = cmd_input.replace("cpscan ","").split()

            for e in get_targets:
                if "http://" in e:
                    e = e.replace("http://","")
                if "https://" in e:
                    e = e.replace("https://","")
                if "www." in e:
                    e = e.replace("www.","")
                if e.endswith("/"):
                    e = e.split("/")[0]

                targets.append(e)

            cpscan(targets)

        else:
            print("  > $ cpscan <target>")
        main()

    elif command == "netscan":
        iface = check_conn()
        fast_portscan = False
        port_scan = False

        if "-fp" in cmd_input or "-pf" in cmd_input:
            fast_portscan = True
            port_scan = True

        if "-p" in cmd_input:
            port_scan = True

        if "-f" in cmd_input:
            if "-fp" in cmd_input or "-pf" in cmd_input:
                pass
            else:
                if "-p" not in cmd_input:
                    printerr("L'opzione '-f' va usata con '-p'")
                    main()
                else:
                    fast_portscan = True

        if len(cmd_input.split()) != 1: # else
            args = ["-fp","-pf","-p","-f"]
            for e in cmd_input.split():
                if e == "netscan":
                    pass
                else:
                    if e not in args:
                        printerr("Argomento non valido: %s"%(e))
                        main()

        netscan(iface, port_scan, fast_portscan)
        main()

    elif command == "bluescan":
        if IsNethunter() == True:
            printerr("Comando non disponibile su Nethunter")
            main()

        bluescan()
        main()

    elif command == "portscan":
        if option:
            check_conn()
            targets = cmd_input.replace("portscan ","").split()
            fast_scan = False
            if "-f" in targets or "--fast_scan" in targets:
                if "-f" in targets:
                    targets.remove("-f")#,"")
                if "--fast_scan" in targets:
                    targets.remove("--fast_scan")#,"")
                fast_scan = True

            target_num = 0
            for ip in targets:
                portscan(ip,None,target_num,fast_scan)
                target_num += 1

        else:
            print("  > $ portscan <target> [target2] [target3] ... [-f/--fast_scan]")
        main()

##### EXP
    elif command == "netsniff":
        if option:
            args = ["start","status","stop","extract","clearlogs"]
            if option not in args:
                printerr("Argomento non valido")
                helpers("netsniff")
                main()

            if option in ["extract","clearlogs","status"]:
                iface = None
            else:
                iface = check_conn()

            netsniff(option, iface)
        else:
            helpers("netsniff")
        main()

    elif command == "nuker":
        if option:
            check_conn()

            target = option
            threads = 3
            limit_pkg = None
            port = 80

            args = cmd_input.split()[2:]
            try:
                if "-t" in args and "-p" in args:
                    printerr("Argomenti '-p' e '-t' non possono essere usati insieme")
                    main()
            except TypeError:
                pass

            try:
                if "-t" in args:
                    try:
                        threads = int(args[int(args.index("-t") + 1)])
                        if threads <= 0:
                            raise ValueError
                    except ValueError:
                        printerr("Numero di threads non valido")
                        main()
                    except IndexError:
                        printerr("Numero di threads richiesto")
                        main()
            except TypeError:
                pass

            try:
                if "-p" in args:
                    try:
                        limit_pkg = int(args[int(args.index("-p") + 1)])
                        if limit_pkg <= 0:
                            raise ValueError
                        threads = None
                    except ValueError:
                        printerr("Numero di pacchetti non valido")
                        main()
                    except IndexError:
                        printerr("Numero di pacchetti richiesto")
                        main()
            except TypeError:
                pass

            try:
                if "-P" in args:
                    try:
                        port = int(args[int(args.index("-P") + 1)])
                        if port <= 0 or port > 65535:
                            raise ValueError
                    except ValueError:
                        printerr("Porta non valida")
                        main()
                    except IndexError:
                        printerr("Porta richiesta")
                        main()
            except TypeError:
                pass

            Args = ["-p","-P","-t"]
            for e in args: # else
                if "nuker" in args:
                    args.remove("nuker")
                if target in args:
                    args.remove(target)
                if "-" not in e:
                    try:
                        args.remove(e)
                    except ValueError:
                        pass

            for e in args:
                if len(args) != 0:
                    if e not in Args:
                        printerr("Argomento non valido: '%s'"%(e))
                        main()

            nuker(target,threads,limit_pkg,port) # avvia
        else:
            print("  > $ nuker <target> [-opzioni]")
    	main()

    elif command == "jtnuke":
        if option:
            check_conn()
            message = "Hello"

            index_packets = None
            index_message = None
            packets = None

            if option in ["-m","-p"]:
                printerr("Le opzioni vanno usate in seguito")
                main()

            if "-p" in cmd_input.split():
                index_packets = cmd_input.split().index("-p") + 1
                try:
                    packets = cmd_input.split()[index_packets]
                    if int(packets):
                        pass
                except ValueError:
                    printerr("Numero di pacchetti non valido: %s"%(packets))
                    main()
                except IndexError:
                    printerr("Numero di pacchetti richiesto")
                    main()

            if "-m" in cmd_input.split():
                index_message = cmd_input.split().index("-m") + 1
                msg = cmd_input.split()[index_message:]
                if "-p" in msg:
                    msg.remove("-p")
                    if str(packets) in msg:
                        msg.remove(str(packets))
                message = ""
                for e in msg:
                    message += e + " "

            jtnuke(option, packets, message)
        else:
            print("  > $ jtnuke <printer> [-p <packets>] [-m <message (default:'Hello')>]")
        main()

    elif command == "wakeup":
        if option:
            check_conn()
            mac = None
            if argument:
                mac = argument
                if len(mac) < 17:
                    printerr("Indirizzo MAC non valido")
                    main()
            ip = option
            wakeup(ip, mac)
        else:
            print("  > $ wakeup <target IP> [target MAC]")
        main()

    elif command == "crackle":
        if option:
            choice = 0
            arguments = cmd_input.split()[1:]
            try:
                if "-i" in arguments:
                    hash = arguments[arguments.index("-i") + 1]
                    crackle("hash_identify",hash)
                    main()
            except IndexError:
                printerr("Hash richiesto")
                main()

            if os.path.isfile(option):
                ext = ["rar","zip"]
                choice = 0
                try:
                    f_ext = option.split(".")[1]
                    if f_ext in ext:
                        try:
                            if len(arguments) == 2:
                                choice = int(arguments[int(arguments.index(option) + 1)]) # = crackobj
                        except ValueError:
                            printerr("Sequenza non valida")
                            main()
                        if ".rar" in option:
                            crackle("rar_crack", option, choice)
                        if ".zip" in option:
                            crackle("zip_crack", option, choice)
                    else:
                        raise IndexError
                except IndexError:
                    printerr("File non valido")
                main()
            else:
                if crackle("hash_check_silently", option, choice) == True:
                    try:
                        if len(arguments) == 2:
                            choice = int(arguments[int(arguments.index(option) + 1)]) # = crackobj
                        crackle("hash_crack", option, choice)
                    except ValueError:
                        printerr("Sequenza non valida")
                else:
                    printerr("Hash non supportato / File non valido")
        else:
            helpers("crackle")
        main()

##### SPOOFING
    elif command == "torghost":
        if option:
            if IsNethunter() == True:
                printerr("Comando non disponibile su Nethunter")
                main()

            options = ["start","switch","stop","status"]
            if option not in options:
                printerr("Argomento non valido")
                main()
            if option == "status":
                torghost(None, "status")
                main()
            else:
                check_conn()
                torghost(option)
        else:
            print("  > $ torghost <start/switch/status/stop>")
        main()

    elif command == "macspoof":
        if option:
            if IsNethunter() == True:
                printerr("Comando non disponibile su Nethunter")
                main()

            options = ["start","stop","status"]
            if option not in options:
                printerr("Argomento non valido")
                main()
            if option == "status":
                macspoof(None, "status")
                main()
            if argument:
                if option == "start":
                    macspoof(argument, "spoof")
                if option == "stop":
                    macspoof(argument, "unspoof")
            else:
                printerr("Interfaccia richiesta")

        else:
            print("  > $ macspoof <start/status/stop> [iface]")
        main()

##### FINAL
    elif command == None:
        main()
    else:
        printerr("Comando non valido: %s"%(cmd_input))
        main()

def check_startup_conn():
    try:
        net_iface = netifaces.gateways()['default'][netifaces.AF_INET][1]
    except KeyError:
        try: # nethunter
            values = []
            get_iface = netifaces.gateways()[2]
            for val in get_iface:
                for e in val:
                    values.append(e)
            iface = str(values[1])
        except KeyError:
            print("")
            printerr("Nessuna interfaccia di rete rilevata")
            printerr("Senza connessione alcuni comandi non sono disponibili")
        except KeyboardInterrupt:
            print("")
    except KeyboardInterrupt:
        print("")

if __name__ == "__main__":
    check_sys()
    if os.geteuid(): # solo utenti root
        print("[%s-%s] Permessi di root richiesti"%(red,end))
        sys.exit()

    sys.stdout.write("\x1B]0; Nelson \x07") # titolo terminale

    os.system("modprobe rfkill && rfkill unblock all") # sblocca tutte le interfaccie (bluetooth, rete)

    sys.stdout.write("\x1b[8;{rows};{cols}t".format(rows=24, cols=80)) # grandezza terminale

    if os.path.isfile("core/modules/lists/whitelist.txt") == False or os.path.isfile("core/modules/lists/blacklist.txt") == False:
        installer("listsdir") # crea possibili cartelle e file mancanti

    if os.path.isfile("core/modules/output/installed") == False:
        installer() # installa tutti i pacchetti

    helpers("logo")
    check_startup_conn()

    torghost(None, "check", "startup")
    macspoof(None, "check", "startup")

    print("")
    helpers("logo","logo_msg")
    print("")
    main()
