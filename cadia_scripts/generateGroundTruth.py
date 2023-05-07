#!/usr/bin/env python3

import socket
import copy
import os
import argparse
import sys
#sys.path.append(r'/root/bvs17Repo/python/')
#from drawPlot import drawPlot

IP_PROTO_TCP = 6
outList = {}
missingTrigger = 0
src = ''
dst = ''
startSeq = {}
endSeq = {}
acks = {0:{},1:{}}
rtt = {}

def groundTruth(fileName, direction, tIndex, sIndex, aIndex, lIndex, tsIndex):
    elem = {}
    global src, dst
    with open(fileName, "r") as inFile:
        dataList = inFile.readlines()
        if direction == 0:
            data = dataList[1].split('\t')
            src = data[0]
            dst = data[1]
        for dataStr in dataList:
            if dataStr[0] == '#':
                continue
            data = dataStr.split('\t')
            if direction not in outList:
                outList[direction] = []
                startSeq[direction] = {}
                endSeq[direction] = {}
            elem['dir'] = direction
            elem['ts'] = int(float(data[tIndex]))
            elem['seq'] = int(data[sIndex])
            elem['ack'] = int(data[aIndex])
            elem['len'] = int(data[lIndex])
            elem['tsval'] = int(data[tsIndex[0]])
            elem['tsecr'] = int(data[tsIndex[1]])
            elem['trig'] = 0
            outList[direction].append(copy.deepcopy(elem))
            expectedAck = elem['seq'] + elem['len']
            startSeq[direction][elem['seq']] = len(outList[direction]) - 1
            if elem['len']:
                endSeq[direction][expectedAck] = len(outList[direction]) - 1
            if elem['ack'] not in acks[not direction]:
                acks[not direction][elem['ack']] = len(outList[direction]) - 1

def calculateRTT():
    direction = 0
    for index, ack in enumerate(acks[direction]):
        if index == 0:
            continue
        starterIndex = endSeq[direction][ack]
        starterTS = outList[direction][starterIndex]['ts']
        starterSeq = outList[direction][starterIndex]['seq']
        ackIndex = acks[direction][ack]
        rtt[starterSeq] = outList[not direction][ackIndex]['ts'] - starterTS #forward leg
        
        nextSeq = outList[not direction][ackIndex]['seq']
        nextIndex = startSeq[not direction][nextSeq]
        assert outList[not direction][nextIndex]['len'] != 0 or nextIndex == len(outList[not direction])-1, "CRAP %d %d" %(nextSeq, len(outList[not direction]))
        if nextIndex == len(outList[not direction]):
            break
        backSeq = outList[not direction][nextIndex]['seq'] + outList[not direction][nextIndex]['len']
        starterTS = outList[not direction][nextIndex]['ts']
        ackIndex = acks[not direction][backSeq]
        rtt[starterSeq] += outList[direction][ackIndex]['ts'] - starterTS #backward leg
    print(rtt)

def main():
    try:
        print("File named connections in cwd has information on bidirectional flows. Choose one (based on number of connections, number of bytes transferred etc) say w_x_y_z and provide following to proceed (column numbers in output/w_x_y_z_A or output/w_x_y_z_B")
        connection = input("input fileNames ")
        tIndex = input("Timestamp Index ")
        sIndex = input("sequence Number Index ")
        aIndex = input("Ack Number Index ")
        lIndex = input("PktLen Index ")
        tsIndex = input("comma separated indices for tsval, tsecr ")
        for flow in [0,1]:
            groundTruth(connection.split(',')[flow], flow, int(tIndex), int(sIndex), int(aIndex), int(lIndex), [int(elt) for elt in tsIndex.split(',')])
        calculateRTT()
    except Exception as e:
        raise e
    

if __name__ == "__main__":
    main()

