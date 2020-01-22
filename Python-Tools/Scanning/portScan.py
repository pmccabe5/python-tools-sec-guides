#!/usr/bin/python3
import socket
from termcolor import colored
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.setdefaulttimeout(2)
host = str(input("[*]Enter a host: "))
def portScanner(port):
    if s.connect_ex((host, port)):
        print(colored("[!!]Port " + str(port) + " is closed", 'red'))
    else:
        print(colored("[+]Port " + str(port) + " is open", 'green'))
for port in range(1, 1000):
    portScanner(port)

