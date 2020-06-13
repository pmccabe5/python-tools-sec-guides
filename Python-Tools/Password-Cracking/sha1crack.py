#!/usr/bin/python3
import hashlib
from urllib.request import urlopen
from termcolor import colored
sha1Hash = input('[*] Enter a SHA1 hash: ')
passwordDump = str(urlopen('https://raw.githubusercontent.com/pmccabe5/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt').read(), 'utf-8')
for passwd in passwordDump.split('\n'):
    possibleHash = hashlib.sha1(bytes(passwd, 'utf-8')).hexdigest()
    if possibleHash == sha1Hash:
        print(colored('[+] Password found: ' + str(passwd), 'green'))
        quit()
    else:
        print(colored('[-] Password guess ' + str(passwd) + ' does not match, trying next possible password', 'red'))
print(colored('[!!] Password not in this list!', 'yellow'))    
