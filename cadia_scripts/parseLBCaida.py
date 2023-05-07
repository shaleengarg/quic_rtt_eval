#!/usr/bin/env python3

import dpkt
import socket
import copy
import os
import argparse
import struct 
import sys 
import numpy as np

secondToNano = 1000 * 1000 * 1000
errors = {}
src = {}
dst = {}

class parseLB():

    def __init__(self, fileName):
        self.connection = {}
        self.outList = []
        self.mergeData = []
        self.IP_PROTO_TCP = 6
        self.IP_HDR_INCREMENTS = 4
        self.TH_SYN = 0x02
        self.TH_FIN = 0x01
        self.debugFile = "debugParseClient"
        self.fileName = fileName
        self.thresholds = [8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096]
        self.secToMicro = 1000 * 1000
        self.windowSize = 6000
        self.window = 1
        self.outDir = os.path.abspath(fileName[0]+"/../output/")

    def runLB(self, srcIP, srcPort, dstIP, dstPort):
        count = 0
        total = 0
        conn = 0
        avg = 0
        maxLen = 0
        debugFd = open(self.debugFile, "w")
        rttFd = open(os.path.join(self.outDir,"lbRTT"), "w")
        gapFd = open(os.path.join(self.outDir,"pktGap"), "w")
        gapRttFd = open(os.path.join(self.outDir,"pktGapRTT"), "w")
        with open(self.fileName[0], 'rb') as input:
            pcapFile = dpkt.pcap.Reader(input)
            for ts, buf in pcapFile:
                tsMicro = int(ts * self.secToMicro)
                total += 1
                rttIndex = 0
                try:
                    ip = dpkt.ip.IP(buf)
                    if ip.p != self.IP_PROTO_TCP:
                        continue
                    tcp = ip.data
                    if socket.inet_ntoa(ip.src) != srcIP or tcp.sport != srcPort or socket.inet_ntoa(ip.dst) != dstIP or tcp.dport != dstPort:
                        continue
                    conKey = srcIP+':'+str(srcPort)+':'+dstIP+':'+str(dstPort)
                    if conKey not in self.connection:
                        self.connection[conKey] = {}
                        self.connection[conKey]['start'] = tsMicro
                        self.connection[conKey]['lastTS'] = tsMicro
                        self.connection[conKey]['tCount'] = [0] * len(self.thresholds)
                        self.connection[conKey]['rttThreshold'] = 0
                        self.connection[conKey]['rttTime'] = 0
                        self.connection[conKey]['rttSeq'] = 0
                    winThreshold = self.connection[conKey]['rttThreshold']
                    interPktGap = tsMicro - self.connection[conKey]['lastTS']
                    wind = self.window
                    adjustWind = 1 if (tsMicro - self.connection[conKey]['start']) % self.windowSize else 0
                    #gapFd.write(str(tcp.seq) + "\t" + str(interPktGap) + "\t" + str(self.window) + "\n")
                    gapFd.write(str(interPktGap) + "\n")
                    if (tsMicro - self.connection[conKey]['start']) >= (self.window * self.windowSize):
                        self.window = (int)((tsMicro - self.connection[conKey]['start']) / self.windowSize) + adjustWind
                        for index in range(len(self.thresholds)):
                            prevThreshold = self.connection[conKey]['tCount'][rttIndex]
                            if rttIndex != len(self.thresholds)-1 and self.connection[conKey]['tCount'][rttIndex+1] != 0:
                                prevThreshold = prevThreshold / self.connection[conKey]['tCount'][rttIndex+1]
                            # if an epoch has no samples, this logic will lead to threshold being set to highest thershold we track, leading to wrong samples from next epoch
                            if index == len(self.thresholds)-1 or self.connection[conKey]['tCount'][index+1] == 0:
                                if prevThreshold <= self.connection[conKey]['tCount'][index]:
                                    rttIndex = index
                            elif prevThreshold <= (self.connection[conKey]['tCount'][index] / self.connection[conKey]['tCount'][index+1]):
                                rttIndex = index
                        #print('\t'.join([str(elt) for elt in self.connection[conKey]['tCount']]), self.window - 1)
                        self.connection[conKey]['tCount'] = [0] * len(self.thresholds)
                        self.connection[conKey]['rttThreshold'] = self.thresholds[rttIndex]
                        #print("\n")
                    #else:
                    for index, threshold in enumerate(self.thresholds):
                        if interPktGap > threshold:
                            self.connection[conKey]['tCount'][index] += 1   
                    if self.window > 1 and interPktGap > winThreshold:
                        rttInferred = tsMicro - self.connection[conKey]['lastTS']
                        if self.connection[conKey]['rttTime']:
                            rttInferred = tsMicro - self.connection[conKey]['rttTime']
                        self.connection[conKey]['rttTime'] = tsMicro
                        self.connection[conKey]['rttSeq'] = tcp.seq
                        dataLen = ip.len-(ip.hl * self.IP_HDR_INCREMENTS)-(tcp.off * self.IP_HDR_INCREMENTS)
                        '''
                        printing this in accordance with tcpProbe, srrt against updated LW.
                        srtt was wrto last LW, so our rtt is calculated for last batch start, printed against next batch start
                        '''
                        rttFd.write(str(self.connection[conKey]['rttSeq']) + "\t" + str(rttInferred) + "\t" + str(winThreshold) + "\n")
                        gapRttFd.write(str(interPktGap) + "\n")
                        #print(tcp.seq, self.window, interPktGap, winThreshold, tsMicro - self.connection[conKey]['start'])
                    self.connection[conKey]['lastTS'] = tsMicro
                except Exception as e:
                    if str(e) not in errors:
                        errors[str(e)] = 0
                    errors[str(e)] += 1
                    count += 1
        for e in errors:
            print(e, errors[e])
        debugFd.write(str(total) + "\t" + str(count) + "\n")
        debugFd.close()
        rttFd.close()
        gapFd.close()
        gapRttFd.close()


def main():
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument("--fwdFile", required=True, help="pcap file in forward direction to be parsed")
        parser.add_argument("--srcIP", required=True)
        parser.add_argument("--srcPort", required=True)
        parser.add_argument("--dstIP", required=True)
        parser.add_argument("--dstPort", required=True)
        args = parser.parse_args()
    except Exception as e:
        raise e
    rttObj = parseLB([args.fwdFile])
    rttObj.runLB(args.srcIP, int(args.srcPort), args.dstIP, int(args.dstPort))
    
if __name__ == "__main__":
    main()

