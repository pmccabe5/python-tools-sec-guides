#!/usr/bin/python3
import socket
from scapy.all import *
from struct import *
import time

def ethAddress(pkt):

    macAddress = '%.2x:%.2x:%.2x:%.2x:%.2x:%.2x' % (pkt[0], pkt[1], pkt[2], pkt[3], pkt[4], pkt[5])
    return macAddress


def main():

    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    
    except:
        print('Error creating socket')
        exit(0)

    while True:

        packet = s.recvfrom(65535)
        packet = packet[0]  

        ethLength = 14
        ethHeader = packet[:ethLength] 
        eth = unpack('!6s6sH', ethHeader)
        ethProtocol = socket.ntohs(eth[2])

        print('Destination MAC Address: ' + ethAddress(packet[0:6]))
        print('Source MAC Address: ' + ethAddress(packet[6:12]))
        print('Protocol: ' + str(ethProtocol) + '\n')

        time.sleep(1)

main()