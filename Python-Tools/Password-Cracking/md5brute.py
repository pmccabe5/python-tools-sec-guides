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


md5Hash = input('[*] Enter a MD5 hash: ')
wordList = input('[*] Enter the path for the password file: ')
tryOpen(wordList)

for word in passfile:
    print(colored('[-] Trying: ' + word.strip('\n'), 'red'))
    encoded = word.encode('utf-8')
    hashed = hashlib.md5(encoded.strip()).hexdigest()

    if hashed == md5Hash:
        print(colored('[+] Password found: ' + word, 'green'))
print(colored('[!!] Password not in list!', 'yellow'))