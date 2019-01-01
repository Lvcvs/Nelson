#!/usr/bin/python
# -*- coding: utf-8 -*-
import re
import os
import socket
import struct
import subprocess
from subprocess import Popen, PIPE

end = '\033[0m'
red = '\033[1;31m'
bright_green = '\033[1;32m'
bright_yellow = '\033[1;33m'

def final():
    import nelson as n
    n.main()

class Waker():
    def makeMagicPacket(self, macAddress): # prepara il pacchetto
        splitMac = str.split(macAddress,':')
        hexMac = struct.pack('BBBBBB', int(splitMac[0], 16),
                             int(splitMac[1], 16),
                             int(splitMac[2], 16),
                             int(splitMac[3], 16),
                             int(splitMac[4], 16),
                             int(splitMac[5], 16))
        self.packet = '\xff' * 6 + macAddress * 16
    def sendPacket(self, packet, destIP, destPort = 7): # invia il pacchetto
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(packet,(destIP,destPort))
        s.close()
    def wake(self, macAddress, destIP, destPort=7):
        self.makeMagicPacket(macAddress)
        self.sendPacket(self.packet, destIP, destPort)

def wakeup(ip, mac):
    print("\n[#] Wakeup (WoL)\n")
    DEVNULL = open(os.devnull, 'w') # nessun output
    pid = Popen(["arp", "-n", ip], stdout=PIPE, stderr=DEVNULL) # mac bersaglio
    s = pid.communicate()[0] # mac bersaglio
    try:
        mac = re.search(r"(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})", s).groups()[0] # mac bersaglio
    except AttributeError:
        print("[%s-%s] Impossibile trovare l'indirizzo MAC di %s"%(red,end, ip))
        print("  > Puoi specificarlo con 'wakeup %s <MAC>'"%(ip))
        final()
    ports = [7,9]
    for port in ports:
        try:
            wol = Waker()
            wol.makeMagicPacket(mac)
            wol.sendPacket(wol.packet, ip, port)
        except KeyboardInterrupt:
            print("[%s-%s] Interrotto"%(red,end))
            final()
    print("\n[%s+%s] Pacchetto inviato"%(bright_green,end))
    print("[#] > %s"%(ip))
    print("[#] > %s\n"%(mac))
