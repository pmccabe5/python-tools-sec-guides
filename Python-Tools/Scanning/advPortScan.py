#!/usr/bin/python3
from socket import *
import optparse
from threading import *
from termcolor import colored

def connScan(host, port):
    try:
        s = socket(AF_INET, SOCK_STREAM)
        s.connect((host, port))
        print(colored('[+] TCP port ' + str(port) + ' is open', 'green'))
    except:
        print(colored('[-] TCP port ' + str(port) + ' is closed', 'red'))
    finally:
        s.close()
    
def portScan(tgtHost, tgtPorts):
    try:
        tgtIP = gethostbyname(tgtHost)
    except:
        print('Unknown host')
    try:
        tgtName = gethostbyaddr(tgtIP)
        print('[+] Scan results for: '+ tgtName[0])
    except:
        print('[+] Scan results for: '+ tgtIP)
    setdefaulttimeout(5)
    for port in tgtPorts:
        t = Thread(target = connScan, args = (tgtHost, int(port)))
        t.start()
   
def main():
    parser = optparse.OptionParser('Usage of Program: ' + '-h <target host> -p <target port>')
    parser.add_option('-H', dest='tgtHost', type='string', help='specify target host')
    parser.add_option('-p', dest='tgtPorts', type='string', help='specify target ports seperated by a comma')
    (options, args) = parser.parse_args()
    tgtHost = options.tgtHost
    tgtPorts = str(options.tgtPorts).split(',')
    if (tgtHost == None) | (tgtPorts[0] == None):
        print(parser.usage)
        exit(0)
    portScan(tgtHost, tgtPorts)        
if __name__ == '__main__':
    main()
