#!/usr/bin/env python3

import socket
import os
import struct
import binascii
import base64
from termcolor import colored

sock = False
sniff = 0

def analyzeUDP(packet):
    
    udp = struct.unpack('!4H', packet[:8])

    sourcePort = udp[0]
    destinationPort = udp[1]
    length = udp[2]
    checksum = udp[3]
    data = packet[8:]

    print(colored('UDP Header', 'green'))
    print('Source Port: %hu' % sourcePort)
    print('Destination Port: %hu' %destinationPort)
    print('Length: %hu' % length)
    print('Checksum: %hu' % checksum)

    return packet

def analyzeTCP(packet):

    tcp = struct.unpack('!2h2I4H', packet[:20])
    
    sourcePort = tcp[0]
    destinationPort = tcp[1]
    sequenceNumber = tcp[2]
    ackNumber = tcp[3]
    offset = tcp[4] >> 12
    reserved = (tcp[5] >> 6) & 0x03ff
    flags = tcp[4] & 0x003f
    window = tcp[5] 
    checksum = tcp[6]
    urgencyPointer = tcp[7]
    data = packet[20:]

    urgency = bool(flags & 0x0020)
    ack = bool(flags & 0x0010)
    psh = bool(flags & 0x0008)
    rst = bool(flags & 0x0004)
    syn = bool(flags & 0x0002)
    fin = bool(flags & 0x0001)

    print(colored('TCP Header', 'magenta'))
    print('Source: %hu' % sourcePort)
    print('Destination: %hu' % destinationPort)
    print('Sequence Number: %u' % sequenceNumber)
    print('ACK Number: %u' % ackNumber)

    print('Flags: ')
    print('Urgency: %d' % urgency)
    print('ACK: %d' % ack)
    print('PSH: %d' % psh)
    print('RST: %d' % rst)
    print('SYN: %d' % syn)
    print('Fin: %d' % fin)

    print('Window Size: %hu' % window)
    print('Checksum: %hu\n' % checksum)

    return packet

def analyze(data):

    header = struct.unpack('!6H4s4s', data[:20])

    version = header[0] >> 12
    ihl = (header[0] >> 8) & 0x0f
    service = header[0] & 0x00ff
    length = header[1]
    ipID = header[2] 

    flags = header[3] >> 13
    frag = header[3] & 0x1fff
    ttl = header[4] >> 8
    protocol = header [4] & 0x00ff
    checksum = header[5]

    source = socket.inet_ntoa(header[6])
    destination = socket.inet_ntoa(header[7])

    packet = data[20:]

    print(colored('IP Header', 'blue'))
    print('Version: %hu' % version)
    print('IHL: %hu' % ihl)
    print('Service: %hu' % service)
    print('Length: %hu' % length)
    print('ID: %hu' % ipID)
    print('Flags: %hu' % flags)
    print('Frag: %hu' % frag)
    print('TTL: %hu' % ttl)
    print('Protocol: %hu' % protocol)
    print('Checksum: %hu' % checksum)
    print('Source: %s' % source)
    print('Destination: %s\n' % destination)

    if protocol == 6:
        transmission = 'TCP'
    elif protocol == 17:
        transmission = 'UDP'
    else:
        transmission = 'Other'
    
    return packet, transmission

def ethernet(packet):

    ip = False
    header = struct.unpack('!6s6sh', packet[:14])

    destination = binascii.hexlify(header[0])
    source = binascii.hexlify(header[1])
    protocol = header[2] >> 8

    data = header[14:]

    print(colored('Ethernet Header', 'yellow'))

    print('Destination MAC: %s:%s:%s:%s:%s:%s' % (destination[0:2].decode('utf-8'), destination[2:4].decode('utf-8'), 
    destination[4:6].decode('utf-8'), destination[6:8].decode('utf-8'), destination[8:10].decode('utf-8'), destination[10:12].decode('utf-8')))

    print('Source MAC: %s:%s:%s:%s:%s:%s' % (source[0:2].decode('utf-8'), source[2:4].decode('utf-8'), 
    source[4:6].decode('utf-8'), source[6:8].decode('utf-8'), source[8:10].decode('utf-8'), source[10:12].decode('utf-8')))

    print('Protocol: %hu\n' % protocol)

    if protocol == 0x08:
        ip = True

    #newData = struct.pack_into('hhl', data)

    return packet, ip


def main():
    
    global sock
    global sniff

    if sock == False:
        sniff = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        sock = True

    data = sniff.recv(2048)
    os.system('clear')

    data, ip = ethernet(data)

    if ip:
        data, protocol = analyze(data)
    else:
        return

    if protocol:
        data = analyzeTCP(data)
    elif not  protocol:
        data = analyzeUDP(data)
    else:
        return
    
while True:
    main()