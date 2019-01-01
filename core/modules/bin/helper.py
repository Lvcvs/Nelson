#!/usr/bin/python
# -*- coding: utf-8 -*-
import os
import sys

reload(sys)
sys.setdefaultencoding('utf8')

end = '\033[0m'
red = '\033[1;31m'
bright_green = '\033[1;32m'
underline = '\033[4m'

def IsNethunter():
    if os.path.isdir("/sdcard"):
        return True
    else:
        return False

def logo():
    from core.modules.bin import version as V
    version = V.version()
    print("""
`7MN.   `7MF'       `7MM
  MMN.    M           MM
  M YMb   M  .gP"Ya   MM  ,pP"Ybd  ,pW"Wq.`7MMpMMMb.
  M  `MN. M ,M'   Yb  MM  8I   `" 6W'   `Wb MM    MM
  M   `MM.M 8M\"\"\"\"\"\"  MM  `YMMMa. 8M     M8 MM    MM
  M     YMM YM.    ,  MM  L.   I8 YA.   ,A9 MM    MM
.JML.    YM  `Mbmmd'.JMML.M9mmmP'  `Ybmd9'.JMML  JMML.
[#] > %s - %sSkull00%s"""%(bright_green+version+end, bright_green,end))

def logo_msg():
    print("[#] > 'help' per i comandi")

def cmd_help(LocalSystem=None):
    print("")
    print("[#] %sComandi%s"%(underline,end))
    print(" os        > Esegue l'input a seguire come comando")
    print(" help      > Questa schermata")
    print(" edit      > Accedi alla shell di modifica")
    print(" status    > Mostra lo stato dei moduli/liste")
    print(" banner    > Mostra il logo")
    print(" reinstall > Reinstalla il programma")
    print(" uninstall > Disinstalla il programma")
    print(" quit/exit > Esci")
    print("")
    print("[#] %sScansioni%s"%(underline,end))
    print(" cpscan    > Cerca pagine di login (Porta 80)")
    print(" netscan   > Scansione di rete")
    print("           # -p > Scansione porte ('-f' > rapida)")
    print(" portscan  > Scansione porte")
    if IsNethunter() == False:
        print(" bluescan  > Scansione bluetooth circostante")
    print("")
    print("[#] %sInformazioni%s"%(underline,end))
    print(" netinfo   > Informazioni di rete")
    print("           # -n > Risultati numerici")
    print("           # -a > Ulteriori informazioni")
    print(" macinfo   > Ottieni informazioni da un indirizzo MAC")
    print(" gethost   > Ottieni hostname tramite IP o indirizzo")
    print(" getmac    > Ottieni indirizzo MAC tramite IP")
    print(" trace     > Traccia le connessioni di un indirizzo")
    print(" whois     > Geo-Localizzatore")
    print("")
    if IsNethunter() == False:
        print("[#] %sSpoofing%s"%(underline,end))
        print(" macspoof  > Nascondi indirizzo MAC")
        print(" torghost  > Nascondi indirizzo IP")
        print("")
    print("[#] %sAttacchi%s"%(underline,end))
    print(" nuker     > Stress Tester")
    print("           # -p <packets> > Pacchetti da inviare")
    print("           # -t <threads> > Threads da usare")
    print("           # -P <porta>   > Porta da stressare (default: 80)")
    print(" jtnuke    > Spammer di stampanti (Porta 9100 jetdirect)")
    print("           # -p <packets> > Richieste da inviare")
    print("           # -m <message> > Messaggio da stampare")
    print(" wakeup    > Invia pacchetto Wake on LAN a un dispositivo")
    print(" crackle   > Hash / rar / zip cracker")
    print(" netsniff  > Sniffer di rete (passwords)")
    print("\n[#] Alcuni comandi richiedono argomenti aggiuntivi\n")

def netsniff_help():
    print("")
    print("[#] %sNetsniff%s"%(underline,end))
    print(" #  start      > Avvia Netsniff")
    print(" #  status     > Stato Netsniff")
    print(" #  stop       > Ferma Netsniff")
    print(" #  extract    > Estrai possibili credenziali")
    print(" #  clearlogs  > Pulisce il file 'NetSniff.log'")
    print("")

def crackle_help():
    print("\n[#] %sCrackle%s"%(underline,end))
    print("\n    $ crackle <[-i] hash / file.[rar/zip]> [choice n.]\n")
    print("    # 0 > a-z (default)")
    print("    # 1 > A-Z")
    print("    # 2 > 0-9")
    print("    # 3 > a-z + 0-9")
    print("    # 4 > A-Z + 0-9")
    print("    # 5 > a-z + A-Z")
    print("    # 6 > a-z + A-Z + 0-9")
    print("    # 7 > a-z + A-Z + 0-9 + .#@+-_*/=%?!<>\n")
    print("[#] %sAlgoritmi Supportati%s"%(underline,end))
    print("    > md5 / sha1 / sha224 / sha256 / sha384 / sha512\n")
