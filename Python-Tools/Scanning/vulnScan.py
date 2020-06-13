#!/usr/bin/python3

import socket, os, sys

def returnBanner(ip, port):
    try:
        socket.setdefaulttimeout(5)
        s = socket.socket()
        s.connect((ip, port))
        banner = s.recv(1024)
        return banner
    except:
        return

def checkVulns(banner, file):
    f = open(file, 'r')
    for line in f.readlines():
        if line.strip('\n') in banner:
            print('[+] Server is Vulnerable' + banner.strip('\n'))
        
    
def main():
    if len(sys.argv) == 2:
        filename = sys.argv[1]
        if not os.path.isfile(filename):
            print('[-] File does not exist')
            exit(0)
        if not os.access(filename, os.R_OK):
            print('[-] Access Denied')
            exit(0)
    else:
        print('[-] Usage: ' + str(sys.argv[0]) + ' <vulnerable filename>')
        exit(0)

    ip = '192.168.226.128'
    for port in range(1, 1025):
        banner = returnBanner(ip, port)
        if banner:
            print('[+] ' + ip + ':' + str(port) + '- ' + banner.decode('utf-8', 'replace').strip('\n'))
            checkVulns(banner, filename)
main()
