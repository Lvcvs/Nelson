#!/usr/bin/python
# -*- coding: utf-8 -*-
# Autore: lgandx (https://github.com/lgandx/PCredz)
# Modificato da: Skull00 (https://www.github.com/Skull00)
import os
import re
import sys
import time
import pcap
import struct
import socket
import logging
import threading
import subprocess
from base64 import b64decode
from threading import Thread
from datetime import datetime

TimeStamp = datetime.now().strftime('%H:%M:%S (%d.%m.%Y)')

http_userfields = [
'log','login','wpname','ahd_username','unickname','nickname','user','user_name','alias','pseudo','email',
'username','_username','userid','form_loginname','loginname','login_id','loginid','session_key','member',
'sessionkey','pop_login','uid','id','user_id','screename','uname','ulogin','acctname','account','uin',
'mailaddress','membername','login_username','login_email','loginusername','loginemail','sign-in',
'j_username',"login-name","name"
]

http_passfields = [
'ahd_password','pass','password','_password','passwd','session_password','sessionpassword','upasswd',
'login_password',"login-password",'loginpassword','form_pw','pw','userpassword','pwd','upassword','login_password',
'passwort','passwrd','wppassword','j_password'
]

Filename = str(os.path.join(os.path.dirname(__file__),"Netsniff.log"))
l= logging.getLogger('Loot')
l.addHandler(logging.FileHandler(Filename,'a'))

def PrintPacket(Filename,Message):
    if os.path.isfile(Filename) == True:
        with open(Filename,"r") as filestr:
            if re.search(re.escape(Message), filestr.read()):
                filestr.close()
                return False
            else:
                return True
    else:
        return True

def IsCookedPcap(version):
    Cooked = re.search('Linux \"cooked\"', version)
    TcpDump = re.search('Ethernet', version)
    Wifi = re.search('802.11', version)
    if Wifi:
        return 1
    if Cooked:
        return 2
    if TcpDump:
        return 3
    else:
        return 3

protocols={6:'tcp',
           17:'udp',
           1:'icmp',
           2:'igmp',
           3:'ggp',
           4:'ipcap',
           5:'ipstream',
           8:'egp',
           9:'igrp',
           29:'ipv6oipv4',
}

def luhn(n):
    r = [int(ch) for ch in str(n)][::-1]
    return (sum(r[0::2]) + sum(sum(divmod(d*2,10)) for d in r[1::2])) % 10 == 0

def Is_Anonymous(data):
    LMhashLen = struct.unpack('<H',data[14:16])[0]
    if LMhashLen == 0 or LMhashLen == 1:
        return False
    else:
        return True

def ParseNTLMHash(data,Challenge):
    PacketLen = len(data)
    if PacketLen > 0:
        SSPIStart = data[:]
        LMhashLen = struct.unpack('<H',data[14:16])[0]
        LMhashOffset = struct.unpack('<H',data[16:18])[0]
        LMHash = SSPIStart[LMhashOffset:LMhashOffset+LMhashLen].encode("hex").upper()
        NthashLen = struct.unpack('<H',data[22:24])[0]
        NthashOffset = struct.unpack('<H',data[24:26])[0]
    if NthashLen == 24:
        NtHash = SSPIStart[NthashOffset:NthashOffset+NthashLen].encode("hex").upper()
        DomainLen = struct.unpack('<H',data[30:32])[0]
        DomainOffset = struct.unpack('<H',data[32:34])[0]
        Domain = SSPIStart[DomainOffset:DomainOffset+DomainLen].replace('\x00','')
        UserLen = struct.unpack('<H',data[38:40])[0]
        UserOffset = struct.unpack('<H',data[40:42])[0]
        User = SSPIStart[UserOffset:UserOffset+UserLen].replace('\x00','')
        writehash = User+"::"+Domain+":"+LMHash+":"+NtHash+":"+Challenge
        return "NTLMv1 hash completo: %s\n"%(writehash), User+"::"+Domain
    if NthashLen > 60:
        NtHash = SSPIStart[NthashOffset:NthashOffset+NthashLen].encode("hex").upper()
        DomainLen = struct.unpack('<H',data[30:32])[0]
        DomainOffset = struct.unpack('<H',data[32:34])[0]
        Domain = SSPIStart[DomainOffset:DomainOffset+DomainLen].replace('\x00','')
        UserLen = struct.unpack('<H',data[38:40])[0]
        UserOffset = struct.unpack('<H',data[40:42])[0]
        User = SSPIStart[UserOffset:UserOffset+UserLen].replace('\x00','')
        writehash = User+"::"+Domain+":"+Challenge+":"+NtHash[:32]+":"+NtHash[32:]
        return "NTLMv2 hash completo: %s\n"%(writehash),User+"::"+Domain
    else:
        return False

def ParseMSKerbv5TCP(Data):
    MsgType = Data[21:22]
    EncType = Data[43:44]
    MessageType = Data[32:33]
    if MsgType == "\x0a" and EncType == "\x17" and MessageType =="\x02":
        if Data[49:53] == "\xa2\x36\x04\x34" or Data[49:53] == "\xa2\x35\x04\x33":
            HashLen = struct.unpack('<b',Data[50:51])[0]
            if HashLen == 54:
                Hash = Data[53:105]
                SwitchHash = Hash[16:]+Hash[0:16]
                NameLen = struct.unpack('<b',Data[153:154])[0]
                Name = Data[154:154+NameLen]
                DomainLen = struct.unpack('<b',Data[154+NameLen+3:154+NameLen+4])[0]
                Domain = Data[154+NameLen+4:154+NameLen+4+DomainLen]
                BuildHash = "$krb5pa$23$"+Name+"$"+Domain+"$dummy$"+SwitchHash.encode('hex')
                return 'MSKerb hash trovato: %s\n'%(BuildHash),"$krb5pa$23$"+Name+"$"+Domain+"$dummy$"
        if Data[44:48] == "\xa2\x36\x04\x34" or Data[44:48] == "\xa2\x35\x04\x33":
            HashLen = struct.unpack('<b',Data[47:48])[0]
            Hash = Data[48:48+HashLen]
            SwitchHash = Hash[16:]+Hash[0:16]
            NameLen = struct.unpack('<b',Data[HashLen+96:HashLen+96+1])[0]
            Name = Data[HashLen+97:HashLen+97+NameLen]
            DomainLen = struct.unpack('<b',Data[HashLen+97+NameLen+3:HashLen+97+NameLen+4])[0]
            Domain = Data[HashLen+97+NameLen+4:HashLen+97+NameLen+4+DomainLen]
            BuildHash = "$krb5pa$23$"+Name+"$"+Domain+"$dummy$"+SwitchHash.encode('hex')
            return 'MSKerb hash trovato: %s\n'%(BuildHash),"$krb5pa$23$"+Name+"$"+Domain+"$dummy$"
        else:
            Hash = Data[48:100]
            SwitchHash = Hash[16:]+Hash[0:16]
            NameLen = struct.unpack('<b',Data[148:149])[0]
            Name = Data[149:149+NameLen]
            DomainLen = struct.unpack('<b',Data[149+NameLen+3:149+NameLen+4])[0]
            Domain = Data[149+NameLen+4:149+NameLen+4+DomainLen]
            BuildHash = "$krb5pa$23$"+Name+"$"+Domain+"$dummy$"+SwitchHash.encode('hex')
            return 'MSKerb hash trovato: %s\n'%(BuildHash),"$krb5pa$23$"+Name+"$"+Domain+"$dummy$"
    else:
        return False

def ParseMSKerbv5UDP(Data):
    MsgType = Data[17:18]
    EncType = Data[39:40]
    if MsgType == "\x0a" and EncType == "\x17":
        if Data[40:44] == "\xa2\x36\x04\x34" or Data[40:44] == "\xa2\x35\x04\x33":
            HashLen = struct.unpack('<b',Data[41:42])[0]
            if HashLen == 54:
                Hash = Data[44:96]
                SwitchHash = Hash[16:]+Hash[0:16]
                NameLen = struct.unpack('<b',Data[144:145])[0]
                Name = Data[145:145+NameLen]
                DomainLen = struct.unpack('<b',Data[145+NameLen+3:145+NameLen+4])[0]
                Domain = Data[145+NameLen+4:145+NameLen+4+DomainLen]
                BuildHash = "$krb5pa$23$"+Name+"$"+Domain+"$dummy$"+SwitchHash.encode('hex')
                return 'MSKerb hash trovato: %s\n'%(BuildHash),"$krb5pa$23$"+Name+"$"+Domain+"$dummy$"
            if HashLen == 53:
                Hash = Data[44:95]
                SwitchHash = Hash[16:]+Hash[0:16]
                NameLen = struct.unpack('<b',Data[143:144])[0]
                Name = Data[144:144+NameLen]
                DomainLen = struct.unpack('<b',Data[144+NameLen+3:144+NameLen+4])[0]
                Domain = Data[144+NameLen+4:144+NameLen+4+DomainLen]
                BuildHash = "$krb5pa$23$"+Name+"$"+Domain+"$dummy$"+SwitchHash.encode('hex')
                return 'MSKerb hash trovato: %s\n'%(BuildHash),"$krb5pa$23$"+Name+"$"+Domain+"$dummy$"
        else:
            HashLen = struct.unpack('<b',Data[48:49])[0]
            Hash = Data[49:49+HashLen]
            SwitchHash = Hash[16:]+Hash[0:16]
            NameLen = struct.unpack('<b',Data[HashLen+97:HashLen+97+1])[0]
            Name = Data[HashLen+98:HashLen+98+NameLen]
            DomainLen = struct.unpack('<b',Data[HashLen+98+NameLen+3:HashLen+98+NameLen+4])[0]
            Domain = Data[HashLen+98+NameLen+4:HashLen+98+NameLen+4+DomainLen]
            BuildHash = "$krb5pa$23$"+Name+"$"+Domain+"$dummy$"+SwitchHash.encode('hex')
            return 'MSKerb hash trovato: %s\n'%(BuildHash),"$krb5pa$23$"+Name+"$"+Domain+"$dummy$"
    else:
        return False

def ParseSNMP(data):
    SNMPVersion = data[4:5]
    if SNMPVersion == "\x00":
        StrLen = struct.unpack('<b',data[6:7])[0]
        return 'Trovato riga SNMPv1 Community: %s\n'%(data[7:7+StrLen])
    if data[3:5] == "\x01\x01":
        StrLen = struct.unpack('<b',data[6:7])[0]
        return 'Trovato riga SNMPv2 Community: %s\n'%(data[7:7+StrLen])

def ParseSMTP(data):
    basic = data[0:len(data)-2]
    OpCode  = ['HELO','EHLO','MAIL','RCPT','SIZE','DATA','QUIT','VRFY','EXPN','RSET']
    if data[0:4] not in OpCode:
        try:
            Basestr = b64decode(basic)
            if len(Basestr)>1:
                if Basestr.decode('ascii'):
                    return 'SMTP Base64 riga decodificata: %s\n'%(Basestr)
        except:
            pass

def ParseSqlClearTxtPwd(Pwd):
    Pwd = map(ord,Pwd.replace('\xa5',''))
    Pw = []
    for x in Pwd:
        Pw.append(hex(x ^ 0xa5)[::-1][:2].replace("x","0").decode('hex'))
    return ''.join(Pw)

def ParseMSSQLPlainText(data):
    UsernameOffset = struct.unpack('<h',data[48:50])[0]
    PwdOffset = struct.unpack('<h',data[52:54])[0]
    AppOffset = struct.unpack('<h',data[56:58])[0]
    PwdLen = AppOffset-PwdOffset
    UsernameLen = PwdOffset-UsernameOffset
    PwdStr = ParseSqlClearTxtPwd(data[8+PwdOffset:8+PwdOffset+PwdLen])
    UserName = data[8+UsernameOffset:8+UsernameOffset+UsernameLen].decode('utf-16le')
    return "MSSQL:\nUsername: %s\nPassword: %s"%(UserName, PwdStr)

def Decode_Ip_Packet(s):
    d={}
    d['version']=(ord(s[0]) & 0xf0) >> 4
    d['header_len']=ord(s[0]) & 0x0f
    d['tos']=ord(s[1])
    d['total_len']=socket.ntohs(struct.unpack('H',s[2:4])[0])
    d['id']=socket.ntohs(struct.unpack('H',s[4:6])[0])
    d['flags']=(ord(s[6]) & 0xe0) >> 5
    d['fragment_offset']=socket.ntohs(struct.unpack('H',s[6:8])[0] & 0x1f)
    d['ttl']=ord(s[8])
    d['protocol']=ord(s[9])
    d['checksum']=socket.ntohs(struct.unpack('H',s[10:12])[0])
    d['source_address']=pcap.ntoa(struct.unpack('i',s[12:16])[0])
    d['destination_address']=pcap.ntoa(struct.unpack('i',s[16:20])[0])
    if d['header_len']>5:
        d['options']=s[20:4*(d['header_len']-5)]
    else:
        d['options']=None
    d['data']=s[4*d['header_len']:]
    return d

def Print_Packet_Details(decoded,SrcPort,DstPort):
    try:
        return 'Protocollo: %s\nSorgenza: %s:%s\nDestinatario: %s:%s' % (protocols[decoded['protocol']],decoded['source_address'],SrcPort,decoded['destination_address'], DstPort)
    except:
        return 'Sorgenza: %s:%s\nDestinatario: %s:%s' % (decoded['source_address'],SrcPort,decoded['destination_address'], DstPort)

def ParseDataRegex(decoded, SrcPort, DstPort):
    HTTPUser = None
    HTTPass = None
    for user in http_userfields:
        user = re.findall('(%s=[^&]+)' % user, decoded['data'], re.IGNORECASE)
        if user:
            HTTPUser = user
    for password in http_passfields:
        passw = re.findall('(%s=[^&]+)' % password, decoded['data'], re.IGNORECASE)
        if passw:
            HTTPass = passw
    SMTPAuth = re.search('AUTH LOGIN|AUTH PLAIN', decoded['data'])
    Basic64 = re.findall('(?<=Authorization: Basic )[^\n]*', decoded['data'])
    FTPUser = re.findall('(?<=USER )[^\r]*', decoded['data'])
    FTPPass = re.findall('(?<=PASS )[^\r]*', decoded['data'])
    HTTPNTLM2 = re.findall('(?<=WWW-Authenticate: NTLM )[^\\r]*', decoded['data'])
    HTTPNTLM3 = re.findall('(?<=Authorization: NTLM )[^\\r]*', decoded['data'])
    NTLMSSP1 = re.findall('NTLMSSP\x00\x01\x00\x00\x00.*[^EOF]*', decoded['data'])
    NTLMSSP2 = re.findall('NTLMSSP\x00\x02\x00\x00\x00.*[^EOF]*', decoded['data'])
    NTLMSSP3 = re.findall('NTLMSSP\x00\x03\x00\x00\x00.*[^EOF]*', decoded['data'],re.DOTALL)
    CCMatch = re.findall('.{30}[^\d][3456][0-9]{3}[\s-]*[0-9]{4}[\s-]*[0-9]{4}[\s-]*[0-9]{4}[^\d]', decoded['data'],re.DOTALL)
    CC = re.findall('[^\d][456][0-9]{3}[\s-]*[0-9]{4}[\s-]*[0-9]{4}[\s-]*[0-9]{4}[^\d]', decoded['data'])
    if Basic64:
        basic = ''.join(Basic64)
        HeadMessage = Print_Packet_Details(decoded,SrcPort,DstPort)
        try:
            Message = 'Trovata autenticazione HTTP di base: %s\n'%(b64decode(basic))
            if PrintPacket(Filename,Message):
                l.warning(HeadMessage)
                l.warning(Message)
        except:
            pass
    if DstPort == 1433 and decoded['data'][20:22]=="\x10\x01" and len(NTLMSSP1) <=0:
        HeadMessage = Print_Packet_Details(decoded,SrcPort,DstPort)
        Message = ParseMSSQLPlainText(decoded['data'][20:])
        if PrintPacket(Filename,Message):
           l.warning(HeadMessage)
           l.warning(Message)
    if DstPort == 88 and protocols.has_key(decoded['protocol']) and protocols[decoded['protocol']] == 'tcp':
        Message = ParseMSKerbv5TCP(decoded['data'][20:])
        if Message:
            HeadMessage = Print_Packet_Details(decoded,SrcPort,DstPort)
            if PrintPacket(Filename,Message[1]):
                l.warning(HeadMessage)
                l.warning(Message[0])
    if DstPort == 88 and protocols.has_key(decoded['protocol']) and protocols[decoded['protocol']] == 'udp':
        Message = ParseMSKerbv5UDP(decoded['data'][8:])
        if Message:
            HeadMessage = Print_Packet_Details(decoded,SrcPort,DstPort)
            if PrintPacket(Filename,Message[1]):
                l.warning(HeadMessage)
                l.warning(Message[0])
    if DstPort == 161:
        Message = ParseSNMP(decoded['data'][8:])
        if Message:
            HeadMessage = Print_Packet_Details(decoded,SrcPort,DstPort)
            if PrintPacket(Filename,Message):
                l.warning(HeadMessage)
                l.warning(Message)
    if DstPort == 143:
        IMAPAuth = re.findall('(?<=LOGIN \")[^\r]*', decoded['data'])
        if IMAPAuth:
            HeadMessage = Print_Packet_Details(decoded,SrcPort,DstPort)
            Message = 'Trovata autenticazione IMAP: "%s\n'%(''.join(IMAPAuth))
            if PrintPacket(Filename,Message):
                l.warning(HeadMessage)
                l.warning(Message)
    if DstPort == 110:
        if FTPUser:
            global POPUser
            POPUser = ''.join(FTPUser)
        if FTPPass:
            try:
                POPUser
                HeadMessage = Print_Packet_Details(decoded,SrcPort,DstPort)
                Message = 'Trovate credenziali POP:\nUsername: %s\nPassword: %s\n'%(POPUser,''.join(FTPPass))
                del POPUser
                if PrintPacket(Filename,Message):
                    l.warning(HeadMessage)
                    l.warning(Message)
            except NameError:
                pass
    if DstPort == 80:
        if (HTTPUser and HTTPass):
            try:
                host = re.findall("(Host: [^\n]+)", decoded['data'])
                get_path = re.findall("(GET [^\n]+)", decoded['data'])
                post_path = re.findall("(POST [^\n]+)", decoded['data'])
                HeadMessage = Print_Packet_Details(decoded,SrcPort,DstPort)
                Message = 'Possibile autenticazione HTTP:\nUsername: %s\nPassword: %s\n'%(HTTPUser[0], HTTPass[0])
                if host:
                    Message += '%s\n' % host[0].strip('\r')
                if get_path:
                    Message += 'Directory: %s\n' % get_path[0].strip('\r')
                if post_path:
                    Message += 'Directory: %s\n' % post_path[0].strip('\r')
                if PrintPacket(Filename,Message):
                    l.warning(HeadMessage)
                    l.warning(Message)
            except:
                pass
    if DstPort == 25 and SMTPAuth or DstPort == 587 and SMTPAuth:
        global SMTPAuthentication
        SMTPAuthentication = '1'
    if DstPort == 25 or DstPort == 587:
        try:
            SMTPAuthentication
            Message = ParseSMTP(decoded['data'][20:])
            if Message:
                HeadMessage = Print_Packet_Details(decoded,SrcPort,DstPort)
                del SMTPAuthentication
                if PrintPacket(Filename,Message):
                    l.warning(HeadMessage)
                    l.warning(Message)
        except NameError:
            pass
    if FTPUser:
        global UserID
        UserID = ''.join(FTPUser)
    if FTPPass and DstPort == 21:
        try:
            HeadMessage = Print_Packet_Details(decoded,SrcPort,DstPort)
            Message = 'FTP Username: %s\n'%(UserID)
            Message+= 'FTP Password: %s\n'%(''.join(FTPPass))
            del UserID
            if PrintPacket(Filename,Message):
                l.warning(HeadMessage)
                l.warning(Message)
        except:
            pass
    if SrcPort == 445:
        SMBRead_userfields = ['Administrator','user', 'email', 'username', 'session_key', 'sessionkey']
        SMBRead_passfields = ['cpassword','password', 'pass', 'password', '_password', 'passwd', 'pwd']
        for users in SMBRead_userfields:
            user = re.findall('(?<=%s )[^\\r]*'%(users), decoded['data'], re.IGNORECASE)
            if user:
               Message = "Nome utente SMB:\n%s:\n%s"%(users, user)
               HeadMessage = Print_Packet_Details(decoded,SrcPort,DstPort)
               if PrintPacket(Filename,Message):
                  l.warning(HeadMessage)
                  l.warning(Message)
        for password in SMBRead_passfields:
            passw = re.findall('(?<=%s )[^\\r]*'%(password), decoded['data'], re.IGNORECASE)
            if passw:
               Message = "Password SMB:\n%s:\n%s"%(password, passw)
               HeadMessage = Print_Packet_Details(decoded,SrcPort,DstPort)
               if PrintPacket(Filename,Message):
                  l.warning(HeadMessage)
                  l.warning(Message)
    if NTLMSSP2:
        global Chall
        Chall = ''.join(NTLMSSP2)[24:32].encode('hex')
    if NTLMSSP3:
        try:
            NTLMPacket = ''.join(NTLMSSP3)
            if Is_Anonymous(NTLMPacket):
                try:
                    Chall
                except NameError:
                    pass
                else:
                    HeadMessage = Print_Packet_Details(decoded,SrcPort,DstPort)
                    Message = ParseNTLMHash(NTLMPacket,Chall)
                    del Chall
                    if PrintPacket(Filename,Message[1]):
                        l.warning(HeadMessage)
                        l.warning(Message[0])
        except:
            pass
    if HTTPNTLM2:
        try:
            Packet = b64decode(''.join(HTTPNTLM2))
            global HTTPChall
            if re.findall('NTLMSSP\x00\x02\x00\x00\x00.*[^EOF]*', Packet,re.DOTALL):
                HTTPChall = ''.join(Packet)[24:32].encode('hex')
        except:
            pass
    if HTTPNTLM3:
        try:
            Packet = b64decode(''.join(HTTPNTLM3))
            if re.findall('NTLMSSP\x00\x03\x00\x00\x00.*[^EOF]*', Packet,re.DOTALL):
                if Is_Anonymous(Packet):
                    try:
                        HTTPChall
                    except NameError:
                        pass
                    else:
                        HeadMessage = Print_Packet_Details(decoded,SrcPort,DstPort)
                        Message = ParseNTLMHash(Packet,HTTPChall)
                        del HTTPChall
                        if PrintPacket(Filename,Message[1]):
                            l.warning(HeadMessage)
                            l.warning(Message[0])
        except:
            pass
    if CC:
        CreditCard = re.sub("\D", "", ''.join(CC).strip())
        CMatch = ''.join(CCMatch).strip()
        if len(CreditCard)<=16:
            if luhn(CreditCard):
                HeadMessage = Print_Packet_Details(decoded,SrcPort,DstPort)
                MessageCC = 'Possibile valido CC (Luhn check OK): %s\n'%(CreditCard)
                MessageMatch= 'Verifica questo match ( %s )\n'%('\033[1m\033[31m'+CMatch+'\033[0m')
                if PrintPacket(Filename,MessageCC):
                    l.warning(HeadMessage)
                    l.warning(MessageCC+MessageMatch)
    else:
        pass

def Print_Packet_Cooked(pktlen, data, TimeStamp):
    if not data:
        return
    if data[14:16]=='\x08\x00':
        decoded=Decode_Ip_Packet(data[16:])
        SrcPort =  struct.unpack('>H',decoded['data'][0:2])[0]
        DstPort =  struct.unpack('>H',decoded['data'][2:4])[0]
        ParseDataRegex(decoded, SrcPort, DstPort)

def Print_Packet_800dot11(pktlen, data, TimeStamp):
    if not data:
        return
    if data[32:34]=='\x08\x00':
        decoded=Decode_Ip_Packet(data[34:])
        SrcPort =  struct.unpack('>H',decoded['data'][0:2])[0]
        DstPort =  struct.unpack('>H',decoded['data'][2:4])[0]
        ParseDataRegex(decoded, SrcPort, DstPort)

def Print_Packet_Tcpdump(pktlen, data, TimeStamp):
    if not data:
        return
    if data[12:14]=='\x08\x00':
        decoded= Decode_Ip_Packet(data[14:])
        if len(decoded['data']) >= 2:
            SrcPort= struct.unpack('>H',decoded['data'][0:2])[0]
        else:
            SrcPort = 0
        if len(decoded['data']) > 2:
            DstPort = struct.unpack('>H',decoded['data'][2:4])[0]
        else:
            DstPort = 0
        ParseDataRegex(decoded, SrcPort, DstPort)

def decode_file(filename,res):
    try:
        p = pcap.pcapObject()
        p.open_offline(filename)
        current_time = datetime.now().strftime('%H:%M:%S (%d.%m.%Y)')
        l.warning('\n # > Sessione sniffing %s\n'%(current_time))
        Version = IsCookedPcap(res)
        if Version == 1:
            thread = Thread(target = p.dispatch, args = (0, Print_Packet_Cooked))
            thread.daemon=True
            thread.start()
            try:
                while thread.is_alive():
                    thread.join(timeout=1)
            except (KeyboardInterrupt, SystemExit):
                threading.Event().set()
        if Version == 2:
            thread = Thread(target = p.dispatch, args = (0, Print_Packet_Cooked))
            thread.daemon=True
            thread.start()
            try:
                while thread.is_alive():
                    thread.join(timeout=1)
            except (KeyboardInterrupt, SystemExit):
                threading.Event().set()
        if Version == 3:
            thread = Thread(target = p.dispatch, args = (0, Print_Packet_Tcpdump))
            thread.daemon=True
            thread.start()
            try:
                while thread.is_alive():
                    thread.join(timeout=1)
            except (KeyboardInterrupt, SystemExit):
                threading.Event().set()
    except: # Exception (truncated file) (unknow file format) (no such file or directory)
        pass

def Run(filename, exit=False):
    p = subprocess.Popen(["file", filename], stdout=subprocess.PIPE)
    res, err = p.communicate()
    decode_file(filename,res)
    current_time = datetime.now().strftime('%H:%M:%S (%d.%m.%Y)')
    Message = '\n # > Terminato %s\n'%(current_time)
    if exit == True:
        Message += ' (Uscita effettuata)'
    l.warning(Message)
