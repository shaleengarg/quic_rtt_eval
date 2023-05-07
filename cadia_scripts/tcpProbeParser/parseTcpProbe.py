#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Jun 22 13:45:15 2021

@author: bhavanavannarthshobhana
"""
import re
import json

'''
when creating the object of this class pass options and output fileName
eg:-
if you want to record the srtt value and timestamp provide the options as
options = {'re':[{'expr': "srtt=(\d+)", 'outName': 'srtt'}, {'expr': ".*([0-9]+[.][0-9]+)\: tcp_probe\:", 'outName': 'timestamp'}]}
'''
class parseTcpProbe():
    options = {}
    output = {}
    outputFile = ""
    
    def __init__(self, parseOptions = {}, outFile = ""):
        self.options = parseOptions
        self.outputFile = outFile

    def parseTcpProbe(self, fileName = ""):
        data = []
        with open(fileName, 'r') as infile:
            rdata = infile.readlines()
        data = rdata[:len(rdata)-1]
        infile.close()
        for line in data:
            for matchExp in self.options['re']:
                outName = matchExp['outName']
                matchVal = re.search(matchExp['expr'], line, re.IGNORECASE)
                if outName not in self.output:
                    self.output[outName] = []
                if matchVal:
                    self.output[outName].append(matchVal.group(1))

    def dumpOutput(self, fileFormat, outKeys):
        if fileFormat == 'json':
            outdata = json.dumps(self.output)
        elif fileFormat == 'column':
            temp = []
            for key in outKeys:
                print(len(self.output[key]))
                if len(temp) == 0:
                    temp = [''] * len(self.output[key])
                for index,elt in enumerate(self.output[key]):
                    temp[index] += '\t'+str(elt)
            outdata = '\n'.join(temp)
        outfile = open(self.outputFile, 'w')
        outfile.write(outdata)
        outfile.flush()
        outfile.close()

    def convertStrtoInt(self, key):
        convertedData = [int(elt, base=16) for elt in self.output[key]]
        self.output[key] = convertedData

    def convertFloattoInt(self, key, factor, divisor):
        convertedData = [int((int(elt) * factor)/divisor) for elt in self.output[key]]
        self.output[key] = convertedData
