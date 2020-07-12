#!/usr/bin/python
"""
This program scans the fct output file and provides the information 
for calculating the throughput and latency numbers needed for Analyzer
"""

import numpy as np
import sys

class FctParser():
    """
    Scan a result file containing completion times for omnet simulation, and
    returns throughputs and latencies for each server/message.
    """

    def __init__(self, fctFile, numHosts, linkBw):
        self.fctFile = fctFile
        self.numHosts = numHosts
        self.linkBw = linkBw
        self.hostBytesSent = [0 for i in range(self.numHosts)]
        self.hostBytesRcvd = [0 for i in range(self.numHosts)]
        self.hostThrouputs = [0.0 for i in range(self.numHosts)]
        self.senderStartSendingTime = [float("inf") for i in range(self.numHosts)]
        self.senderStopSendingTime = [0.0 for i in range(self.numHosts)]
        self.throughputs = [0.0 for i in range(self.numHosts)]
        self.delays = []
        self.qdelays = []
        self.slowdowns = []
        self.parse()

    def parse(self):
        with open(self.fctFile,'r') as fctFileIn:
            for line in fctFileIn:
                numbersStr = line.split(' ')
                src = int(numbersStr[0])
                dst = int(numbersStr[1])
                msgCreationTime = float(numbersStr[5])
                msgCompletionTime = float(numbersStr[6])
                msgSchedTime = float(numbersStr[7])
                idealTime = float(numbersStr[8])
                slowdown = max(1.0, msgSchedTime / idealTime)
                msgSizeInBytes = int(numbersStr[4])

                self.delays.append(msgSchedTime)
                self.qdelays.append(max(0.0,msgSchedTime - idealTime))
                self.slowdowns.append(slowdown)

                self.hostBytesSent[src] += msgSizeInBytes
                self.hostBytesRcvd[dst] += msgSizeInBytes

                if(msgCreationTime < self.senderStartSendingTime[src]):
                    self.senderStartSendingTime[src] = msgCreationTime
                if(msgCompletionTime > self.senderStopSendingTime[src]):
                    self.senderStopSendingTime[src] = msgCompletionTime

        for i in range(self.numHosts):
            if(self.hostBytesSent[i] > 0):
                self.throughputs[i] = (self.hostBytesSent[i] * 8.0 / ((self.senderStopSendingTime[src] - self.senderStartSendingTime[src]) * self.linkBw))
            else:
                self.throughputs[i] = 0.0

        
        