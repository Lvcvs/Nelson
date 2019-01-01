#!/usr/bin/python
# -*- coding: utf-8 -*-
import os
import readline

commands_list = ["os","uninstall","help","quit","exit","edit","banner","status","reinstall","cpscan","crackle","getmac","jtnuke","macinfo","wakeup","trace","nuker","netinfo","netscan","netsniff","whois","portscan","gethost"]

# Rileva se il sistema è Nethunter
if os.path.isdir("/sdcard"):
    pass
else:
    commands_list += ["torghost","macspoof","bluescan"]

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
        except IndexError: #return None # Default
            if text.split()[0]:
                def list_folder(path): # Mostra contenuti cartella
                    if path.startswith(os.path.sep) or path.startswith(".."):
                        basedir = os.path.dirname(path) # directory base
                        contents = os.listdir(basedir)
                        contents = [os.path.join(basedir, d) for d in contents] # add back the parent
                    else:
                        contents = os.listdir(os.curdir) # relative path
                    return contents
                def sys_completer(text, state): # Our custom completer function
                    options = [x for x in list_folder(text) if x.startswith(text)]
                    if os.path.isdir(options[state]):
                        return options[state] + "/"
                    else:
                        return options[state] + " "
                readline.set_completer(sys_completer)
            else:
                return None

def normal():
    completer = Completer(commands_list)
    readline.set_completer(completer.complete)
    readline.parse_and_bind('tab: complete')
    readline.set_completer_delims(' \t\n`~!@#$%^&*()-=+[{]}\\|;:\'",<>?')
