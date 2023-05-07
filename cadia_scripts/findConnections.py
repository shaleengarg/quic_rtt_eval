#!/usr/bin/env python3

import dpkt
import socket
import copy
import os
import argparse
import struct 

IP_PROTO_TCP = 6
IP_HDR_INCREMENTS = 4
output = {}
debugFile = "debugParseCaida"
secondToNano = 1000 * 1000 * 1000
errors = {}

def findConnections(fileName, outDir):
    dirList = os.listdir(outDir)
    oFile = open("commonFiles", "w")
    with open(fileName, 'r') as iFile:
        data = iFile.readlines()
        for record in data:
            if record.startswith('#'):
                continue
            elt = record.split()
            if int(elt[1]) >= (int(elt[2])/2):
                fileName = elt[0].rsplit('_', 1)[0] + "_A"
                if fileName in dirList:
                    output[fileName] = [elt[1],elt[2]]
    with open("output/sequenceDistribution_A") as inFile:
        data = inFile.readlines()
        for record in data:
            if record.startswith('#'):
                continue
            elt = record.split()
            if elt[0] in output and int(elt[1]) >= (int(elt[2])/2):
                oFile.write(elt[0] + "\t" + elt[1] + "\t" + output[elt[0]][0] + "\n")
    iFile.close()
    oFile.close()
    inFile.close()

def main():
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument("--inputFile", required=True, help="pcap file to be parsed")
        args = parser.parse_args()
    except Exception as e:
        raise e
    outDir = os.path.abspath(os.path.abspath(__file__) + '/../output')
    if not os.path.exists(outDir):
        os.makedirs(outDir)
    findConnections(args.inputFile, outDir)

if __name__ == "__main__":
    main()

