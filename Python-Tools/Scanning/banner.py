#!/usr/bin/python3
import socket
def returnBanner(ip, port):
    try:
        socket.setdefaulttimeout(5)
        s = socket.socket()
        s.connect((ip, port))
        banner = s.recv(1024)
        return banner
    except:
        return
def main():
    ip = str(input('[*] Enter an ip address: '))
    for port in range(1, 1025):
        banner = returnBanner(ip, port)
        if banner:
            print('[+] ' + ip + ':' + str(port) + '- ' + banner.decode('utf-8', 'replace').strip('\n'))
main()
