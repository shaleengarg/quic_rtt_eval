#!/usr/bin/env python3

import socket
import os
import argparse
import sys
import time

class Client():

    def __init__(self, addr, port, duration):
        self.serveraddr = addr
        self.serverport = port
        self.duration = duration
        self.ping_pong = "This is ping pong experiment %d"
        self.multiple_request = []
        self.think_request = []

    def prepareMultiPayload(self):
        self.multiple_request.append("This is multiple request echo experiment FIRST ONE OF THE BATCH %d")
        self.multiple_request.append("This is multiple request echo experiment SECOND ONE OF THE BATCH %d")
        self.multiple_request.append("This is multiple request echo experiment THIRD ONE OF THE BATCH %d")
        self.multiple_request.append("This is multiple request echo experiment FOURTH ONE OF THE BATCH %d")
        self.multiple_request.append("This is multiple request echo experiment FIFTH ONE OF THE BATCH %d")

    def prepareThinkPayload(self):
        self.think_request.append("This is think echo experiment FIRST ONE OF THE BATCH %d")
        self.think_request.append("This is think echo experiment SECOND ONE OF THE BATCH %d")
        self.think_request.append("This is think echo experiment THIRD ONE OF THE BATCH %d")
        self.think_request.append("This is think echo experiment FOURTH ONE OF THE BATCH %d")
        self.think_request.append("This is think echo experiment FIFTH ONE OF THE BATCH %d")

    def startEchoClient(self, sendData, sendLen = 0):
        if sendData and sendLen:
            self.ping_pong = sendData 
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.connect((self.serveraddr, self.serverport))
            start = time.time()
            batch = 0
            while (time.time() - start) < self.duration:
                batch += 1
                dataSend = bytearray(self.ping_pong %batch, 'utf-8')
                startIndex = len(dataSend) - sendLen if sendLen else 0
                client.sendall(dataSend[startIndex:])
                dataLen = len(dataSend[startIndex:])
                while (dataLen):
                    data = client.recv(4096)
                    dataLen -= len(data)

    def startMultiClient(self, sendData, sendLen = 0):
        if not sendData:
            self.prepareMultiPayload()
        else:
            self.multiple_request.append(sendData)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.connect((self.serveraddr, self.serverport))
            client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            start = time.time()
            batch = 0
            while (time.time() - start) < self.duration:
                dataLen = 0
                batch += 1
                for msg in self.multiple_request:
                    dataSend = bytearray(msg %batch, 'utf-8')
                    startIndex = len(dataSend) - sendLen if sendLen else 0
                    client.sendall(dataSend[startIndex:])
                    dataLen += len(dataSend[startIndex:])
                print(dataLen)
                while (dataLen):
                    data = client.recv(4096)
                    dataLen -= len(data)
                    print(data, len(data))
                print(dataLen, "\n\n")

    def startThinkClient(self, sendData, sendLen = 0):
        if not sendData:
            self.prepareThinkPayload()
        else:
            self.think_request.append(sendData)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.connect((self.serveraddr, self.serverport))
            start = time.time()
            batch = 0
            while (time.time() - start) < self.duration:
                batch += 1
                dataLen = 0
                for msg in self.think_request:
                    dataSend = bytearray(msg %batch, 'utf-8')
                    startIndex = len(dataSend) - sendLen if sendLen else 0
                    client.sendall(dataSend[startIndex:])
                    dataLen += len(dataSend[startIndex:])
                print(dataLen)
                while (dataLen):
                    data = client.recv(4096)
                    dataLen -= len(data)
                print("\n\n")


def main():
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument("--serverAddr", required=True, help="IP address of server to connect to")
        parser.add_argument("--serverPort", required=True, help="Port of server to connect to", type=int)
        parser.add_argument("--duration", help="Duration of test in seconds", type=int, default=1)
        parser.add_argument("--inFile", help="Data to be sent will be read from the mentioned input file", default=None)
        args = parser.parse_args()
        client = Client(args.serverAddr, args.serverPort, args.duration)
        inData = None
        with open(args.inFile, "r") as inFileFd:
            inData = inFileFd.readlines()[0] + " %d"
        client.startMultiClient(inData, 1448)
        #client.startEchoClient(inData, 724)
    except Exception as e:
        raise e
    

if __name__ == "__main__":
    main()

