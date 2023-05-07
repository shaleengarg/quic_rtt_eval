#!/usr/bin/env python3

import dpkt
import socket
import copy
import os
import argparse
import struct 

secondToNano = 1000 * 1000 * 1000
errors = {}
src = {}
dst = {}

class parseClient():

    def __init__(self, fileName):
        self.outList = []
        self.IP_PROTO_TCP = 6
        self.IP_HDR_INCREMENTS = 4
        self.TH_SYN = 0x02
        self.TH_FIN = 0x01
        self.debugFile = "debugParseClient"
        self.fileName = fileName

    def parsePkt(self):
        count = 0
        total = 0
        conn = 0
        avg = 0
        maxLen = 0
        global src, dst
        debugFd = open(self.debugFile, "w")
        connTerminate = False
        with open(self.fileName, 'rb') as input:
            pcapFile = dpkt.pcap.Reader(input)
            for ts, buf in pcapFile:
                total += 1
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    ip = eth.data
                    if ip.p != self.IP_PROTO_TCP:
                        continue
                    tcp = ip.data
                    data = {}
                    if tcp.flags == self.TH_SYN:
                        src['ip'] = ip.src
                        src['port'] = tcp.sport
                        dst['ip'] = ip.dst
                        dst['port'] = tcp.dport
                    if tcp.flags & self.TH_FIN:
                        connTerminate = True
                    if ip.src == src['ip']:
                        data['Forw'] = 1
                    else:
                        data['Forw'] = 0
                    data['TS'] = ts * secondToNano
                    data['Seq'] = tcp.seq
                    data['Flags'] = tcp.flags
                    data['Ack'] = tcp.ack
                    data['Len'] = ip.len-(ip.hl * self.IP_HDR_INCREMENTS)-(tcp.off * self.IP_HDR_INCREMENTS)
                    if tcp.flags & self.TH_SYN:
                        data['Len'] = 1
                        data['Syn'] = 1
                    data['TSVal'], data['TSEcr'] = struct.unpack('>II', [options[1] for options in dpkt.tcp.parse_opts(tcp.opts) if options[0] == 8][0])
                    debugFd.write(str(type(tcp)) + "\t" + socket.inet_ntoa(ip.src) + "\t" + socket.inet_ntoa(ip.dst) + "\t")
                    debugFd.write(str(ip.len) + "\t" + str(ip.hl) + "\t" + str(tcp.off * self.IP_HDR_INCREMENTS) + "\t" + str(tcp.seq) + "\n")
                    if not connTerminate:
                        self.outList.append(data)
                except Exception as e:
                    if str(e) not in errors:
                        errors[str(e)] = 0
                    errors[str(e)] += 1
                    count += 1
        for e in errors:
            print(e, errors[e])
        debugFd.write(str(total) + "\t" + str(count) + "\n")
	

class parseClientTimestamp(parseClient):

    def __init__(self, fileName):
        super.__init__(fileName)

    def findTriggers(self):
        pass


class parseClientSequence(parseClient):

    def __init__(self, fileName):
        super().__init__(fileName)
        self.lastFPkt = {} #tracks last received packet in forward direction
        self.lastBPkt = {} #tracks last received packet in backward direction
        self.forStart = {} #tracks index of fresh sequences in forward direction
        self.forEnd = {} #tracks index of fresh sequences in forward direction to ease lookup during ACK in backward direction
        self.bacStart = {} #tracks index of fresh sequences in backward direction
        self.bacEnd = {} #tracks index of fresh sequences in backward direction to ease lookup during ACK in forward direction
        self.forTrigger = {} #contains index of ACKs in backward direction triggered by this packet in forward direction
        self.bacTrigger = {} #contains index of ACKs in forward direction triggered by this packet in backward direction
        self.retransmissions = {}
        self.forRange = {}
        self.bacRange = {}
        self.retransmissions['fwd'] = {}
        self.retransmissions['bwd'] = {}
        self.reorder = {}
        self.reorder['fwd'] = 0
        self.reorder['bwd'] = 0
        self.outDir = os.path.abspath(os.path.abspath(fileName) + '/../output')
        if not os.path.exists(self.outDir):
            os.makedirs(self.outDir)
    
    def adjustforStartEnd(self, pivot):
        if pivot not in self.forEnd:
            for sequence in self.forStart:
                index = self.forStart[sequence]
                if pivot > self.outList[index]['Seq'] and pivot < self.outList[index]['Seq'] + self.outList[index]['Len']:
                    self.forStart[pivot] = index
                    self.forEnd[pivot] = index
                    break
        return

    def adjustbacStartEnd(self, pivot):
        if pivot not in self.bacEnd:
            for sequence in self.bacStart:
                index = self.bacStart[sequence]
                if pivot > self.outList[index]['Seq'] and pivot < self.outList[index]['Seq'] + self.outList[index]['Len']:
                    self.bacStart[pivot] = index
                    self.forEnd[pivot] = index
                    break
        return

    '''
    Things to clarify
    1. for reordered packets should we ignore the rtt sample or associate with corresponding packet accordingly move self.last inside if block
    2. 
    '''
    def findTriggerNoDelay(self):
        self.parsePkt()
        for index, pkt in enumerate(self.outList):
            freshData = pkt['Seq'] + pkt['Len'] if pkt['Len'] else -1
            if pkt['Forw'] == 1:
                if freshData > 0:
                    if freshData in self.forEnd:
                        assert self.forTrigger[self.forStart[pkt['Seq']]][0] == -1, "BLUNDER CHECK OUT FWD"
                        self.retransmissions['fwd'][pkt['Seq']] = 1
                    self.forStart[pkt['Seq']] = index
                    self.forEnd[freshData] = index
                    self.forTrigger[index] = [-1, -1]
                # if old ACK comes since the window has advanced stack will ignore ACK
                freshAck = pkt['Ack'] if len(self.lastFPkt) and pkt['Ack'] > self.lastFPkt['Ack'] else -1
                if freshAck > 0:
                    self.adjustbacStartEnd(freshAck)
                    ackIndex = self.bacEnd[freshAck]
                    ackedPkt = self.outList[ackIndex]
                    assert ackedPkt['Seq'] not in self.retransmissions['bwd'] or pkt['TSEcr'] == ackedPkt['TSVal'], "DEBUG BWD RETRANSMISSION %d %d %d" %(ackedPkt['Seq'], pkt['TSEcr'], ackedPkt['TSVal'])
                    #lastAck = self.bacStart[self.lastFPkt['Ack']] if self.lastFPkt['Ack'] in self.bacEnd else -1
                    #self.bacTrigger[ackIndex] = [index, lastAck]
                    self.bacTrigger[ackIndex] = [index, freshAck]
                if not len(self.lastFPkt) or freshAck > 0:
                    self.lastFPkt = pkt #moved inside if block since its only being used for pure fresh ACK recognition
            else:
                if freshData > 0:
                    if freshData in self.bacEnd:
                        # packet from client side could be dropped in middlebox, so we may see duplicate REQ-RESP
                        lastPktTS = self.outList[self.bacStart[pkt['Seq']]]['TSVal']
                        assert self.bacTrigger[self.bacStart[pkt['Seq']]][0] == -1 or lastPktTS < pkt['TSVal'], "BLUNDER CHECK OUT BWD"
                        self.retransmissions['bwd'][pkt['Seq']] = 1
                    self.bacStart[pkt['Seq']] = index
                    self.bacEnd[freshData] = index
                    self.bacTrigger[index] = [-1, -1]
                freshAck = pkt['Ack'] if len(self.lastBPkt) and pkt['Ack'] > self.lastBPkt['Ack'] else -1
                if freshAck > 0:
                    self.adjustforStartEnd(freshAck)
                    ackIndex = self.forEnd[freshAck]
                    ackedPkt = self.outList[ackIndex]
                    #updated the condition to >= as in the case of filling the hole, TSEcr will be of the recent packet 
                    assert ackedPkt['Seq'] not in self.retransmissions['fwd'] or pkt['TSEcr'] >= ackedPkt['TSVal'], "DEBUG FWD RETRANSMISSION"
                    #lastAck = self.forStart[self.lastBPkt['Ack']] if self.lastBPkt['Ack'] in self.forEnd else -1
                    #self.forTrigger[ackIndex] = [index, lastAck]
                    self.forTrigger[ackIndex] = [index, freshAck]
                if not len(self.lastBPkt) or freshAck > 0:
                    self.lastBPkt = pkt #moved inside if block since its only being used for pure fresh ACK recognition
        self.printTriggers('_ND')

    '''
    Things to note
    1. ACK is associated with earliest sequence, reordered ACK will be ignored if ACK received already covered the corresponding transmission
    '''
    def findTriggerDelay(self):
        eFIndex = -1
        eBIndex = -1
        self.parsePkt()
        for index, pkt in enumerate(self.outList):
            freshData = pkt['Seq'] + pkt['Len'] if pkt['Len'] else -1
            if pkt['Forw'] == 1:
                #when packet with sequence number same as ACK from the last S->C is not received yet
                if len(self.lastBPkt) and pkt['Len'] and pkt['Seq'] == self.lastBPkt['Ack']:
                    eFIndex = index
                if freshData > 0:
                    if freshData in self.forEnd:
                        assert self.forTrigger[self.forStart[pkt['Seq']]][0] == -1, "BLUNDER CHECK OUT FWD"
                        self.retransmissions['fwd'][pkt['Seq']] = 1
                    self.forStart[pkt['Seq']] = index
                    self.forEnd[freshData] = index
                self.forTrigger[index] = [-1, -1]
                # condition below formulated to avoid duplicate ACK and reordered old ACK
                freshAck = pkt['Ack'] if len(self.lastFPkt) and pkt['Ack'] > self.lastFPkt['Ack'] else -1 
                if freshAck > 0:
                    if eBIndex > 0 and self.outList[eBIndex]['Seq'] + self.outList[eBIndex]['Len'] != freshAck:
                        ackIndex = eBIndex
                    else:
                        ackIndex = self.bacEnd[freshAck] if freshAck in self.bacEnd else -1
                    if ackIndex >= 0:
                        ackedPkt = self.outList[ackIndex]
                        assert ackedPkt['Seq'] not in self.retransmissions['bwd'] or pkt['TSEcr'] == ackedPkt['TSVal'], "DEBUG FWD RETRANSMISSION"
                        self.bacTrigger[ackIndex] = [index, freshAck]
                        #self.bacTrigger[ackIndex] = [index, eBIndex]
                    #when packet with seq same as ACK is already received
                    eBIndex = self.bacStart[freshAck] if freshAck in self.bacStart else -1
                if not len(self.lastFPkt) or freshAck > 0:
                    self.lastFPkt = pkt #update done inside loop as this field is used for ACK processing alone
            else:
                #when packet with sequence number same as ACK from the last C->S is not received yet
                if len(self.lastFPkt) and pkt['Len'] and pkt['Seq'] == self.lastFPkt['Ack']:
                    eBIndex = index
                if freshData > 0:
                    if freshData in self.bacEnd:
                        lastPktTS = self.outList[self.bacStart[pkt['Seq']]]['TSVal']
                        assert self.bacTrigger[self.bacStart[pkt['Seq']]][0] == -1 or lastPktTS < pkt['TSVal'], "BLUNDER CHECK OUT BWD"
                        self.retransmissions['bwd'][pkt['Seq']] = 1
                    self.bacStart[pkt['Seq']] = index
                    self.bacEnd[freshData] = index
                self.bacTrigger[index] = [-1, -1]
                # condition below formulated to avoid duplicate ACK and reordered old ACK
                freshAck = pkt['Ack'] if len(self.lastBPkt) and pkt['Ack'] > self.lastBPkt['Ack'] else -1
                if freshAck > 0:
                    if eFIndex > 0 and self.outList[eFIndex]['Seq'] + self.outList[eFIndex]['Len'] != freshAck:
                        ackIndex = eFIndex
                    else:
                        ackIndex = self.forEnd[freshAck] if freshAck in self.forEnd else -1
                    if ackIndex >= 0:
                        ackedPkt = self.outList[ackIndex]
                        assert ackedPkt['Seq'] not in self.retransmissions['fwd'] or pkt['TSEcr'] == ackedPkt['TSVal'], "DEBUG BWD RETRANSMISSION"
                        #self.forTrigger[ackIndex] = [index, self.lastFPkt['Seq'] + self.lastFPkt['Len']]
                        self.forTrigger[ackIndex] = [index, freshAck]
                        #self.forTrigger[ackIndex] = [index, eFIndex]
                    #when packet with seq same as ACK is already received
                    eFIndex = self.forStart[freshAck] if freshAck in self.forStart else -1
                if not len(self.lastBPkt) or freshAck > 0:
                    self.lastBPkt = pkt #update done inside loop as this field is used for ACK processing alone
        self.printTriggers('_D')

    def printTriggers(self, suffix = ''):

        #triggerFd = open(self.outDir+"/triggerSequence", "w")
        pairSeqF = open(self.outDir + "/pairForwardSequence" + suffix, "w")
        pairRttF = open(self.outDir + "/pairForwardRTT" + suffix, "w")
        pairSeqB = open(self.outDir + "/pairBackwardSequence" + suffix, "w")
        pairRttB = open(self.outDir + "/pairBackwardRTT" + suffix, "w")
        print("P1 P2", len(self.bacTrigger)) 
        print("P2 P3", len(self.forTrigger))
        
        for pkt in self.forTrigger:
            if self.forTrigger[pkt][0] == -1:
                continue
            ackIndex = self.forTrigger[pkt][0]
            pairSeqF.write(str(self.outList[pkt]['Seq']) + "\t" + str(self.outList[ackIndex]['Seq']) + "\t" + str(pkt) + "\t" + str(ackIndex) + "\n")
            rtt = int((self.outList[ackIndex]['TS'] - self.outList[pkt]['TS'])/1000)
            unAck = self.forTrigger[pkt][1]
            if unAck > 0:
                pairRttF.write(str(unAck) + "\t" + str(rtt) + "\n")
                #pairRttF.write(str(self.outList[unAck]['Seq']) + "\t" + str(rtt) + "\n")
            else:
                print("UNEXPECTED FORW")
        pairSeqF.close()
        pairRttF.close()

        for pkt in self.bacTrigger:
            if self.bacTrigger[pkt][0] == -1:
                continue
            ackIndex = self.bacTrigger[pkt][0]
            pairSeqB.write(str(self.outList[pkt]['Seq']) + "\t" + str(self.outList[ackIndex]['Seq']) + "\t" + str(pkt) + "\t" + str(ackIndex) + "\n")
            rtt = int((self.outList[ackIndex]['TS'] - self.outList[pkt]['TS'])/1000)
            unAck = self.bacTrigger[pkt][1]
            if unAck > 0:
                pairRttB.write(str(unAck) + "\t" + str(rtt) + "\n")
                #pairRttB.write(str(self.outList[unAck]['Seq']) + "\t" + str(rtt) + "\n")
            else:
                print("UNEXPECTED BACK")
        #record trigger for flows in forward, on file trigger in current dircetory
        
        '''for pkt in self.forTrigger:
            secondTrigger = self.forTrigger[pkt]
            firstTrigger = self.bacTrigger[secondTrigger] if secondTrigger >= 0 else -1
            if firstTrigger >= 0 and secondTrigger >= 0:
                triggerFd.write(str(self.outList[firstTrigger]['Seq']) + "\t" + str(self.outList[secondTrigger]['Seq']) + "\t" + str(self.outList[pkt]['Seq']) + "\n")
        triggerFd.close()'''
        pairSeqB.close()
        pairRttB.close()

def main():
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument("--inputFile", required=True, help="pcap file to be parsed")
        args = parser.parse_args()
    except Exception as e:
        raise e
    rttObj = parseClientSequence(args.inputFile)
    rttObj.findTriggerNoDelay()

if __name__ == "__main__":
    main()

