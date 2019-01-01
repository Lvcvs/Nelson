#!/usr/bin/python
# -*- coding: utf-8 -*-
import os
import readline

end = '\033[0m'
red = '\033[1;31m'
bright_green = '\033[1;32m'
bright_yellow = '\033[1;33m'
underline = '\033[4m'

def final():
    import nelson as n
    n.main()

class Completer(object):
    def __init__(self, options):
        self.options = sorted(options)
    def complete(self, text, state):
        if state == 0:
            if text:
                self.matches = [s for s in self.options if s and s.startswith(text)]
            else:
                self.matches = self.options[:]
        try:
            return self.matches[state] + " "
        except IndexError:
            return None # Default
# Lists
def whitelist(arg,target=None):
    whitelist = "core/modules/lists/whitelist.txt"
    if os.path.isfile(whitelist) == False:
        os.system("touch %s"%(whitelist))

    if arg == "show":
        print("\n[#] Whitelist")
        show = open(whitelist,"r").read().splitlines()
        if len(show) == 0:
            print("[%s-%s] Nessun elemento"%(red,end))
        else:
            for e in show:
                print("[%s+%s] %s"%(bright_green,end, e))

    if arg == "add":
        # codice di verifica
        f = open(whitelist, "r").readlines()
        if target+"\n" in f:
            print("[%s-%s] Dispositivo in lista"%(red,end))
            main()
        # writer
        f = open(whitelist, "a")
        f.write(target+"\n")
        f.close()
        print("[%s+%s] '%s' Aggiunto"%(bright_green,end, target))

    if arg == "removeall":
        os.system("rm %s && touch %s"%(whitelist, whitelist))
        print("[%s+%s] Tutti gli elementi rimossi"%(bright_green,end))

    if arg == "remove":
        contents = []
        f = open(whitelist, "r").readlines()
        if len(f) == 0:
            print("[%s-%s] Lista vuota"%(red,end))
            main()
        for line in f:
            if "\n" in line:
                line = line.replace("\n","")
            contents.append(line)
        Removed = False
        for line in contents:
            if target == line:
                contents.remove(line)
                Removed = True
                break
        if Removed == True:
            f = open(whitelist, "w")
            contents.sort() # ordina la lista
            for line in contents:
                f.write(line+"\n")
            print("[%s+%s] '%s' rimosso"%(bright_green,end, target))
            f.close()
        else:
            print("[%s-%s] '%s' non in lista"%(red,end, target))

def blacklist(arg,target=None):
    blacklist = "core/modules/lists/blacklist.txt"
    if os.path.isfile(blacklist) == False:
        os.system("touch %s"%(blacklist))

    if arg == "show":
        print("\n[#] Blacklist")
        show = open(blacklist,"r").read().splitlines()
        if len(show) == 0:
            print("[%s-%s] Nessun elemento"%(red,end))
        else:
            for e in show:
                print("[%s+%s] %s"%(bright_green,end, e))

    if arg == "add":
        # codice di verifica
        f = open(blacklist, "r").readlines()
        if target+"\n" in f:
            print("[%s-%s] Dispositivo in lista"%(red,end))
            main()
        # writer
        f = open(blacklist, "a")
        f.write(target+"\n")
        f.close()
        print("[%s+%s] '%s' Aggiunto"%(bright_green,end, target))

    if arg == "removeall":
        os.system("rm %s && touch %s"%(blacklist, blacklist))
        print("[%s+%s] Tutti gli elementi rimossi"%(bright_green,end))

    if arg == "remove":
        contents = []
        f = open(blacklist, "r").readlines()
        if len(f) == 0:
            print("[%s-%s] Lista vuota"%(red,end))
            main()
        for line in f:
            if "\n" in line:
                line = line.replace("\n","")
            contents.append(line)
        Removed = False
        for line in contents:
            if target == line:
                contents.remove(line)
                Removed = True
                break
        if Removed == True:
            f = open(blacklist, "w")
            contents.sort() # ordina la lista
            for line in contents:
                f.write(line+"\n")
            print("[%s+%s] '%s' rimosso"%(bright_green,end, target))
            f.close()
        else:
            print("[%s-%s] '%s' non in lista"%(red,end, target))
# helper
def Help():
    print("")
    print("[#] %sListe%s:"%(underline,end))
    print(" whitelist")
    print(" blacklist")
    print("")
    print("[#] %sComandi%s:"%(underline,end))
    print(" help   > Questa schermata")
    print(" back   > Torna al menu")
    print(" show   > Vedi contenuto lista")
    print(" add    > Aggiungi a lista un IP")
    print(" remove > Rimuovi da lista un IP")
    print("")

# main
def main():
    # input
    bash = u"\u250C"+3*u"\u2500"+"[ %sEdit%s ]"%(bright_green,end)+"\n"+u"\u2514"+u"\u2500"+u"\u257C"+" # "
    try:
        cmd_input = raw_input(bash)
    except (KeyboardInterrupt,EOFError):
        print("\n[#] Sei stato riportato al menu")
        final()
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
    if command == "back":
        print("[#] Sei stato riportato al menu")
        final()
    elif command == "help":
        Help()
        main()
    elif command == "show":
        if option:
            if option == "whitelist":
                whitelist("show")
                print("")
                main()
            if option == "blacklist":
                blacklist("show")
                print("")
                main()
            if option == "all":
                whitelist("show")
                blacklist("show")
                print("")
                main()
            else:
                print("[%s-%s] Argomento non valido"%(red,end))
        else:
            print("  > $ show <all/lista>")
        main()
    elif command == "add":
        if option:
            if option == "whitelist" or option == "blacklist":
                if argument:
                    if option == "whitelist":
                        whitelist("add",argument)
                    if option == "blacklist":
                        blacklist("add",argument)
                    main()
                else:
                    print("[%s-%s] Dispositivo richiesto"%(red,end))
            else:
                print("[%s-%s] File non valido"%(red,end))
        else:
            print("  > $ add <lista> <IP>")
        main()
    elif command == "remove":
        if option:
            if option == "whitelist" or option == "blacklist":
                if argument:
                    if option == "whitelist":
                        if argument == "all":
                            whitelist("removeall")
                        else:
                            whitelist("remove",argument)
                    if option == "blacklist":
                        if argument == "all":
                            blacklist("removeall")
                        else:
                            blacklist("remove",argument)
                    main()
                else:
                    print("[%s-%s] Dispositivo richiesto"%(red,end))
            else:
                print("[%s-%s] File non valido"%(red,end))
        else:
            print("  > $ remove <lista> <IP>/<all>")
        main()
##### FINAL
    else:
        if cmd_input == "": main()
        print("[%s-%s] Comando non valido: %s"%(red,end, command))
    main()

def control():
    edit_cmd_list = ["help","back","show","add","remove","whitelist","blacklist"]
    completer = Completer(edit_cmd_list)
    readline.set_completer(completer.complete)
    readline.parse_and_bind('tab: complete')
    Help()
    main()
