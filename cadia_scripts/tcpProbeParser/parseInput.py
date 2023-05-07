#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Jun 22 13:45:15 2021

@author: bhavanavannarthshobhana
"""
#import sys
import re
#sys.path.append(r'~/distributed_systems/tcpProbeParser/')
from parseTcpProbe import parseTcpProbe 
import os

tcpProbe_inputFile = "/users/bvs17/strict/32K/MRCSRO/testTraceMRCSRO"
microToMilli = 1000
secToMilli = 1000
secToMicro = 1000000
srttColumn = 0
timeColumn = 1
nxtColumn = 2
unaColumn = 3

def getMillisecData(iFile = '', oFile = ''):
    if not len(iFile) or not len(oFile):
        return 
    with open(iFile, 'r') as inputFile, open(oFile, 'w') as outputFile:
        dataList = inputFile.readlines()
        startTime = float(dataList[0].split()[timeColumn]) * secToMicro
        for data in dataList:
            elt = data.split()
            elt.append(str(((float(elt[nxtColumn]) - float(elt[unaColumn])) % (pow(2,32)-1))/float(elt[srttColumn])))
            elt[srttColumn] = str(float(elt[srttColumn])/microToMilli)
            elt[timeColumn] = str(float(elt[timeColumn]) * secToMicro - startTime)
            outputFile.write('\t'.join(elt))
            outputFile.write('\n')
    inputFile.close()
    outputFile.close()

def getRttFromSrtt(iFile = '', oFile = ''):
    if not len(iFile) or not len(oFile):
        return
    outputList = []
    with open(iFile, 'r') as inputFile, open(oFile, 'w') as outputFile:
        dataList = inputFile.readlines()
        prevSample = []
        for index, data in enumerate(dataList):
            curSample = data.split()
            if len(prevSample) > 0:
                rtt = int(curSample[1]) * 8 - int(prevSample[1]) * 7
                if int(curSample[0]) == int(prevSample[0]):
                    continue
                    #outputList[-1] = str(curSample[0]) + "\t" + str(rtt)
                else:
                    outputList.append(str(curSample[0]) + "\t" + str(rtt))
            prevSample = curSample
        outputFile.write('\n'.join(outputList))
        inputFile.close()
        outputFile.close()

def main():
    outDir = os.path.abspath(os.path.abspath(tcpProbe_inputFile)+'/../output/')
    outFile = os.path.abspath(os.path.abspath(__file__) + '/../output')
    plotFile = os.path.abspath(os.path.abspath(__file__) + '/../../plots')
    srttMicroFile = os.path.basename(tcpProbe_inputFile).strip('.txt') + '_srtt_micro'
    srttFile = os.path.basename(tcpProbe_inputFile).strip('.txt') + '_srtt'
    rttFile = os.path.basename(tcpProbe_inputFile).strip('.txt') + '_rtt'
    if not os.path.exists(outDir):
        os.makedirs(outDir)
    if not os.path.exists(outFile):
        os.makedirs(outFile)
    if not os.path.exists(plotFile):
        os.makedirs(plotFile)
    tcpProbe_outputMicroFile = os.path.join(outFile, srttMicroFile)
    srtt_options = {'re':[{'expr': "srtt=(\d+)", 'outName': 'srtt'},{'expr': ".*\s([0-9]+[.][0-9]+)\: tcp_probe\:", 'outName':'timestamp'},{'expr': "snd_nxt=(0x[a-f0-9]+)", 'outName': 'nxt'},{'expr': "snd_una=(0x[a-f0-9]+)", 'outName': 'una'}]}
    srtt_sample = parseTcpProbe(srtt_options, tcpProbe_outputMicroFile)
    srtt_sample.parseTcpProbe(tcpProbe_inputFile)
    srtt_sample.convertStrtoInt('nxt')
    srtt_sample.convertStrtoInt('una')
    srtt_sample.dumpOutput('column',['una', 'srtt'])
    tcpProbe_outputFile = os.path.join(outFile, srttFile)
    getRttFromSrtt(tcpProbe_outputMicroFile, os.path.join(outDir, rttFile))
    #getMillisecData(tcpProbe_outputMicroFile, tcpProbe_outputFile)
    if not os.path.islink(os.path.join(plotFile, 'srttTcpProbeClient')):
        os.symlink(tcpProbe_outputFile, os.path.join(plotFile, 'srttTcpProbeClient'))
    print('Output File Location: \n' + tcpProbe_outputFile)

if __name__ == "__main__":
    main()

