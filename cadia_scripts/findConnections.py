#!/usr/bin/env python3

import dpkt
import socket
import copy
import os
import argparse
import struct 

output = {}

def findConnections(fileNames, outDir):
    dirList = os.listdir(outDir)
    oFile = open("commonFiles", "w")
    with open(fileNames[0], 'r') as iFile:
        data = iFile.readlines()
        for record in data:
            if record.startswith('#'):
                continue
            elt = record.split()
            if int(elt[1]) >= (int(elt[2])/2):
                fileName = elt[0].rsplit('_', 1)[0] + "_A"
                if fileName in dirList:
                    output[fileName] = [elt[1],elt[2]]
    with open(fileNames[1], 'r') as inFile:
        data = inFile.readlines()
        for record in data:
            if record.startswith('#'):
                continue
            elt = record.split()
            if elt[0] in output and int(elt[1]) >= (int(elt[2])/2):
                oFile.write(elt[0] + "\t\t" + elt[1] + "\t" + output[elt[0]][0] + "\n")
    iFile.close()
    oFile.close()
    inFile.close()

def main():
    try:
    inputFiles = ['output/sequenceDistribution_B', 'output/sequenceDistribution_A']
    except Exception as e:
        raise e
    outDir = os.path.abspath(os.path.abspath(__file__) + '/../output')
    if not os.path.exists(outDir):
        os.makedirs(outDir)
    findConnections(inputFiles, outDir)

if __name__ == "__main__":
    main()

