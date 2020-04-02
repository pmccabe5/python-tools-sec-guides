#!/usr/bin/python3

import pexpect

PROMPT = ['# ', '>>> ', '> ', '\$ ', '~ ']

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
    child.expect(PROMPT)
    return child

def sendcmd(child, cmd):

    child.sendline(cmd)
    child.expect(PROMPT)
    print(child.before.decode())

def main():

    host = input('Enter a host: ')
    user = input('Enter a username: ')
    passwd = input('Enter a password: ')
    child = connect(host, user, passwd)
    sendcmd(child, 'cat /etc/shadow | grep root; ps; uname -a')

main()
