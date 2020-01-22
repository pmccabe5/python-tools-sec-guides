#!/usr/bin/python3
import ftplib
def anonlogin(hostname):
    try:
        ftp = ftplib.FTP(hostname)
        ftp.login('anonymous', 'anonymous')
        print('[*] ' + hostname + ' FTP Anonymous Login Success')
        ftp.quit()
        return True
    except Exception as e:
        print('[-] ' + hostname + 'FTP Anonymous Login Failed')
host = str(input('Enter a host: '))
anonlogin(host)
