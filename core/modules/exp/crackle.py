#!/usr/bin/python
# -*- coding: utf-8 -*-
import os
import sys
import time
import hashlib # hash
import zipfile # file zip
import rarfile # file rar
import itertools # wordlist generator
from datetime import datetime

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

def get_characters(choice):
    if choice == 0: characters, abr = "abcdefghijklmnopqrstuvwxyz", "a-z"
    if choice == 1: characters, abr = "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "A-Z"
    if choice == 2: characters, abr = "0123456789", "0-9"
    if choice == 3: characters, abr = "abcdefghijklmnopqrstuvwxyz1234567890", "a-z + 0-9"
    if choice == 4: characters, abr = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890", "A-Z + 0-9"
    if choice == 5: characters, abr = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", "a-z + A-Z"
    if choice == 6: characters, abr = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890", "a-z + A-Z + 0-9"
    if choice == 7: characters, abr = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.#@+-_*/=%?!<>", "a-z + A-Z + 0-9 + .#@+-_*/=%?!<>"
    return characters, abr

################################################################################
#### HASHCRACK
def get_algorithm(hash): # hash crack
    if len(hash) == 32: return "md5"
    elif len(hash) == 40: return "sha1"
    elif len(hash) == 56: return "sha224"
    elif len(hash) == 64: return "sha256"
    elif len(hash) == 96: return "sha384"
    elif len(hash) == 128: return "sha512"
    else:
        print("[%s-%s] Hash non supportato o non valido"%(red,end))
        final()

def hash_checker(argument,hash): # hash crack
    if argument == "identify":
        message = "[%s+%s] Algoritmo: "%(bright_green,end)
        if len(hash) == 32: message += "md5"
        elif len(hash) == 40: message += "sha1"
        elif len(hash) == 56: message += "sha224"
        elif len(hash) == 64: message += "sha256"
        elif len(hash) == 96: message += "sha384"
        elif len(hash) == 128: message += "sha512"
        else:
            print("[%s-%s] Hash non supportato o non valido"%(red,end))
            final()
        print message

    if argument == "check":
        lengths = [32,40,56,64,96,128]
        if len(hash) not in lengths:
            print("[%s-%s] Hash non valido"%(red,end))
            final()

    if argument == "check_silently":
        lengths = [32,40,56,64,96,128]
        if len(hash) not in lengths:
            return False
        else:
            return True

def hash_crack(hash,choice): # hash crack
    characters, abr = get_characters(choice)
    algorithm = get_algorithm(hash)
    if algorithm == "md5": h = hashlib.md5
    if algorithm == "sha1": h = hashlib.sha1
    if algorithm == "sha224": h = hashlib.sha224
    if algorithm == "sha256": h = hashlib.sha256
    if algorithm == "sha384": h = hashlib.sha384
    if algorithm == "sha512": h = hashlib.sha512
    try:
        print("\n[#] Crackle\n")

        hash_checker("identify",hash)
        print("[#] Sequenza: %s (%s)\n"%(choice, abr))

        s_time = datetime.now().strftime('%H:%M:%S')

        print("[%s+%s] Avviato: %s\n"%(bright_green,end, s_time))

        tested = 0
        start = time.time()
        for leng in range(1, len(characters)+1):
            it = itertools.product(characters, repeat=leng) # genera la wordlist da usare
            for passw in it:
                passwd = "".join(passw)
                crypt = h(passwd).hexdigest()

                tested += 1
                sys.stdout.write("\r[%s*%s] Parole testate: %s"%(bright_yellow,end, tested))
                sys.stdout.flush()

                if hash.upper() == crypt.upper():
                    stop = time.time()
                    e_time = datetime.now().strftime('%H:%M:%S')
                    print("\n\n[%s+%s] Terminato: %s"%(bright_green,end, e_time))
                    print("[%s*%s] Durata: %s secondi\n"%(bright_yellow,end, round((stop-start), 2)))
                    print("[%s+%s] Testo decifrato\n"%(bright_green,end))
                    for e in ["[#] Hash > %s"%(hash), "[%s+%s]      > %s"%(bright_green,end, passwd)]:
                        check_len_message(e)
                        print(e)
                    print("")
                    final()

        # se nessun risultato
        stop = time.time()
        print("\n")
        print("[%s*%s] Durata: %s secondi\n"%(bright_yellow,end, round((stop-start), 2)))
        print("[%s-%s] Nessun Risultato\n"%(red,end))
        final()
    except KeyboardInterrupt:
        print("\n\n[%s-%s] Interrotto\n"%(red,end))
        final()
################################################################################
#### ZIPPER
def zipper_crack(filename,choice):
    characters, abr = get_characters(choice)

    if os.path.exists(filename) == False:
        print("[%s-%s] File non trovato"%(red,end))
        final()
    try:
        ext = filename.split(".")[1]
        if ext not in ("zip","rar"):
            print("[%s-%s] Archivio non valido"%(red,end))
            final()
    except IndexError:
        print("[%s-%s] Archivio non valido"%(red,end))
        final()

    print("\n[#] Crackle\n")
    print("[#] File: %s"%(filename))
    print("[#] Sequenza: %s (%s)\n"%(choice, abr))

    s_time = datetime.now().strftime('%H:%M:%S')
    start_ = time.time() # avvio

    print("[%s+%s] Cracking avviato: %s"%(bright_green,end, s_time))
    print("\n[#] Visualizzato: Lunghezza Password / Password Testate")
    tested = 0
    psw_found = False
    for leng in range(1, len(characters)+1):
        if psw_found == True:
            break

        it = itertools.product(characters, repeat=leng) # genera la wordlist da usare

        if ext == "zip":
            zipFile = zipfile.ZipFile(filename, "r")
            for passw in it:
                tested += 1
                sys.stdout.write("\r[#] > %s / %s"%(leng, tested))
                sys.stdout.flush()
                try:
                    passwd = "".join(passw)
                    zipFile.setpassword(passwd)
                    zipFile.extractall()

                    # se la password è corretta
                    psw_found = True
                    break
                except RuntimeError: # password sbagliata
                    pass
                except zipfile.BadZipfile:
                    pass
                except KeyboardInterrupt:
                    print("\n\n[%s-%s] Interrotto\n"%(red,end))
                    final()
                except:
                    pass

        if ext == "rar":
            rarFile = rarfile.RarFile(filename,mode="r")
            if rarFile.needs_password() == False:
                print("[%s-%s] L'archivio non richiede password"%(red,end))
                final()
            for passw in it:
                tested += 1
                sys.stdout.write("\r[%s*%s] > %s / %s"%(bright_yellow,end, leng, tested))
                sys.stdout.flush()
                try:
                    passwd = "".join(passw)
                    rarFile.setpassword(passwd)
                    rarFile.extractall()

                    # se la password è corretta
                    psw_found = True
                    break
                except rarfile.RarWrongPassword:
                    pass
                except KeyboardInterrupt:
                    print("\n\n[%s-%s] Interrotto\n"%(red,end))
                    final()


    end_ = time.time() # termine
    elapsed = round((end_-start_), 2)
    e_time = datetime.now().strftime('%H:%M:%S')

    print("\n\n[%s+%s] Terminato: %s"%(bright_green,end, e_time))
    print("[%s*%s] Durata: %s secondi\n"%(bright_yellow,end, elapsed))

    if psw_found == True:
        print("[%s+%s] Password Trovata: %s\n"%(bright_green,end, passwd))
    else:
        print("[%s-%s] Nessuna Password Trovata\n"%(red,end))
