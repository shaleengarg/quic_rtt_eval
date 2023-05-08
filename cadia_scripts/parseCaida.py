#!/usr/bin/env python3

import dpkt
import socket
import copy
import os
import argparse
import struct 

IP_PROTO_TCP = 6
IP_HDR_INCREMENTS = 4
outputFiles = {}
debugFile = "debugParseCaida"
secondToNano = 1000 * 1000 * 1000
errors = {}
distinctSeq = {}

def parsePkt(fileName, outDir, suffix, fwd, pktFilter):
    count = 0
    total = 0
    conn = 0
    avg = 0
    data = {}
    maxLen = 0
    filterString = ''
    for rules in pktFilter:
        rule = rules.split(':')
        filterString += rule[1] + '_'
    filterString = filterString.rsplit('_', 1)[0]#needs refactoring to support any combination of filter
    debugFd = open(debugFile+"_"+suffix, "w")
    with open(fileName, 'rb') as input:
        pcapFile = dpkt.pcap.Reader(input)
        for ts, buf in pcapFile:
            try:
                total += 1
                ip = dpkt.ip.IP(buf)
                if ip.p != IP_PROTO_TCP:
                    continue
                tcp = ip.data
                debugFd.write(str(type(tcp)) + "\t" + socket.inet_ntoa(ip.src) + "\t" + socket.inet_ntoa(ip.dst) + "\t")
                if fwd:
                    output = socket.inet_ntoa(ip.src) + "_" + str(tcp.sport) + "_" + socket.inet_ntoa(ip.dst) + "_" + str(tcp.dport)
                else:
                    output = socket.inet_ntoa(ip.dst) + "_" + str(tcp.dport) + "_" + socket.inet_ntoa(ip.src) + "_" + str(tcp.sport)
                if suffix:
                    output += "_" + suffix
                if output not in outputFiles:
                    outputFiles[output] = {'distinctSeq': 0, 'pkts': []}
                    conn += 1
                data['ts'] = str(ts * secondToNano)
                data['seq'] = str(tcp.seq)
                data['ack'] = str(tcp.ack)
                data['len'] = str(ip.len-(ip.hl * IP_HDR_INCREMENTS)-(tcp.off * IP_HDR_INCREMENTS))
                data['tsval'], data['tsecr'] = struct.unpack('>II', [options[1] for options in dpkt.tcp.parse_opts(tcp.opts) if options[0] == 8][0])
                debugFd.write(str(output) + "\t" + str(ip.len) + "\t" + str(ip.hl) + "\t" + str(tcp.off * IP_HDR_INCREMENTS) + "\t" + str(tcp.seq) + "\n")
                lastPkt = outputFiles[output]['pkts'][-1] if len(outputFiles[output]['pkts']) else None
                outputFiles[output]['pkts'].append(copy.deepcopy(data))
                if lastPkt and int(lastPkt['seq']) != int(data['seq']):
                    outputFiles[output]['distinctSeq'] += 1
                print(output, total)
            except Exception as e:
                if str(e) not in errors:
                    errors[str(e)] = 0
                errors[str(e)] += 1
                count += 1
    for e in errors:
        print(e, errors[e])
    if not len(outputFiles):
        return
    for output in outputFiles:
        avg += len(outputFiles[output]['pkts'])
        if len(outputFiles[output]['pkts']) > maxLen:
            maxLen = len(outputFiles[output]['pkts'])
    avg /= len(outputFiles)
    sd = open(os.path.join(outDir, "sequenceDistribution_"+suffix), "w")
    sd.write("#conID" + "\t" + "|distinctSeq|" + "\t" + "totalPkt" + "\n")
    for output in outputFiles:
        if len(filterString) and filterString not in output:
            continue
        sd.write(output + "\t\t\t" + str(outputFiles[output]['distinctSeq']) + "\t\t" + str(len(outputFiles[output]['pkts'])) + "\n")
        if len(outputFiles[output]['pkts']) > avg:
            fd = open(os.path.join(outDir, output), "w")
            fd.write("#" + "EP1(0)" + "\t" + "EP2(1)" + "\t" + "pktNum(2)" + "\t" + "seqNum(3)" + "\t" + "ackNum(4)" + "\t" + "TS(ns)(5)" + "\t" + "Relative TS(micros)(6)" + "\t" + "dataLen(7)" + "\t" + "TSVal(8)" + "\t" + "TSEcr(9)" + "\n")
            for pktCount, elt in enumerate(outputFiles[output]['pkts']):
                if pktCount == 0:
                    startTime = int(float(elt['ts']))
                relTime = str((int(float(elt['ts'])) - startTime) / 1000) #in micro
                outList = output.split('_')
                fd.write(outList[0] + ":" + outList[1] + "\t" + outList[2] + ":" + outList[3] + "\t" + str(pktCount) + "\t" + elt['seq'] + "\t" + elt['ack'] + "\t" + elt['ts'] + "\t" + relTime + "\t" + elt['len'] + "\t" + str(elt['tsval']) + "\t" + str(elt['tsecr']) + "\n")
            fd.close()
    sd.close()
    debugFd.write(str(total) + "\t" + str(count) + "\t" + str(conn) + "\t" + str(avg) + "\t"  + str(maxLen) + "\n")
			

def main():
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument("--inputFile", required=True, help="pcap file to be parsed")
        parser.add_argument("--suffix", help="suffix to be attached to output file")
        parser.add_argument("--fwd", help="pcap represents forward flow if 1", default = 1, type=int)
        parser.add_argument("--filter", help="list of filters to apply src, dest, sport, dport")
        args = parser.parse_args()
    except Exception as e:
        raise e
    outDir = os.path.abspath(os.path.abspath(__file__) + '/../output')
    if not os.path.exists(outDir):
        os.makedirs(outDir)
    pktFilter = []
    if args.filter:
        pktFilter = args.filter.split(',')
    parsePkt(args.inputFile, outDir, args.suffix, args.fwd, pktFilter)

if __name__ == "__main__":
    main()

