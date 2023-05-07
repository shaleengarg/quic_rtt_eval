#!/usr/bin/env python3

import socket
import copy
import os
import argparse
import sys

class Server():

    def __init__(self, addr, port):
        self.serveraddr = addr
        self.serverport = port

    def startServer(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.bind((self.serveraddr, self.serverport))
            server.listen()
            conn, addr = server.accept()
            with conn:
                print("Connected to ", addr)
                while True:
                    data = conn.recv(1024)
                    if not data:
                        break
                    conn.sendall(data)

def main():
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument("--serverAddr", required=True, help="IP address to listen on")
        parser.add_argument("--serverPort", required=True, help="Port to listen on", type=int)
        args = parser.parse_args()
        server = Server(args.serverAddr, args.serverPort)
        server.startServer()
    except Exception as e:
        raise e
    

if __name__ == "__main__":
    main()

