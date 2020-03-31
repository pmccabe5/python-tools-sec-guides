#!/usr/bin/python3
import subprocess

def changeMAC(interface, mac):
    
    subprocess.call(['ifconfig', interface, 'down'])
    subprocess.call(['ifconfig', interface, 'hw', 'ether', mac])
    subprocess.call(['ifconfig', interface, 'up'])

def main():
    
    interface = input('Enter in a network interface: ')
    mac = input('Enter in a new MAC address: ')

    before = subprocess.check_output(['ifconfig', interface])
    changeMAC(interface, mac)
    after = subprocess.check_output(['ifconfig', interface])

    if before == after:
        print('Failed to change MAC')
    else:
        print('Successfully changed MAC to '+ mac + ' on interface: ' + interface)

main()