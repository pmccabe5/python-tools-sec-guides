#!/usr/bin/python3
import hashlib
from termcolor import colored

def tryOpen(wordlist):
    global passfile
    try:
        passfile = open(wordlist, 'r')
    except:
        print('[!!] No such file at the path')
        quit()


sha1Hash = input('[*] Enter a SHA1 hash: ')
wordList = input('[*] Enter the path for the password file: ')
tryOpen(wordList)

for word in passfile:
    print(colored('[-] Trying: ' + word.strip('\n'), 'red'))
    encoded = word.encode('utf-8')
    hashed = hashlib.sha1(encoded.strip()).hexdigest()

    if hashed == sha1Hash:
        print(colored('[+] Password found: ' + word, 'green'))
print(colored('[!!] Password not in list!', 'yellow'))