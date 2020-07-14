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
        self.senderMaxStartSendingTime = [float(0) for i in range(self.numHosts)]
        self.senderStopSendingTime = [0.0 for i in range(self.numHosts)]
        self.throughputs = [0.0 for i in range(self.numHosts)]
        self.inloads = [0.0 for i in range(self.numHosts)]
        self.delays = []
        self.qdelays = []
        self.adelays = []
        self.tdelays = []
        self.slowdowns = []
        self.msgSizes = []
        self.binnedSlowdowns = {}
        self.binnedAdmitFractions = {}
        self.binnedTransportFractions = {}
        self.binnedQueueFractions = {}
        self.admitDelayFractions = []
        self.transportDelayFractions = []
        self.queueDelayFractions = []
        for i in range(10):
            self.binnedSlowdowns[i] = []
            self.binnedAdmitFractions[i] = []
            self.binnedTransportFractions[i] = []
            self.binnedQueueFractions[i] = []
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
                self.msgSizes.append(msgSizeInBytes)

                admittedTime = float(numbersStr[9])
                firstEnqueueTime = float(numbersStr[10])

                self.delays.append(msgSchedTime)
                # print(numbersStr)
                admitDelay = max(0.0,admittedTime - msgCreationTime)
                transportDelay = max(0.0,firstEnqueueTime - admittedTime)
                assert(msgSchedTime - admitDelay - transportDelay >= 0)
                queueDelay = max(0.0,msgSchedTime - admitDelay - transportDelay)
                self.qdelays.append(queueDelay)
                self.adelays.append(admitDelay)
                self.tdelays.append(transportDelay)
                self.admitDelayFractions.append(admitDelay/msgSchedTime)
                self.transportDelayFractions.append(transportDelay/msgSchedTime)
                self.queueDelayFractions.append(queueDelay/msgSchedTime)
                assert(queueDelay >= 0)
                assert(admitDelay >= 0)
                assert(transportDelay >= 0)
                self.slowdowns.append(slowdown)

                self.hostBytesSent[src] += msgSizeInBytes
                self.hostBytesRcvd[dst] += msgSizeInBytes

                if(msgCreationTime < self.senderStartSendingTime[src]):
                    self.senderStartSendingTime[src] = msgCreationTime
                if(msgCompletionTime > self.senderStopSendingTime[src]):
                    self.senderStopSendingTime[src] = msgCompletionTime
                if(msgCreationTime > self.senderMaxStartSendingTime[src]):
                    self.senderMaxStartSendingTime[src] = msgCreationTime

        for i in range(self.numHosts):
            if(self.hostBytesSent[i] > 0):
                self.throughputs[i] = (self.hostBytesSent[i] * 8.0 / ((self.senderStopSendingTime[src] - self.senderStartSendingTime[src]) * self.linkBw))
                self.inloads[i] = (self.hostBytesSent[i] * 8.0 / ((self.senderMaxStartSendingTime[src] - self.senderStartSendingTime[src]) * self.linkBw))
            else:
                self.throughputs[i] = 0.0
                self.inloads[i] = 0.0

        for i in range(len(self.slowdowns)):
            msgSize = self.msgSizes[i]
            key = int(np.log10(msgSize))
            self.binnedSlowdowns[key].append(self.slowdowns[i])
            self.binnedAdmitFractions[key].append(self.admitDelayFractions[i])
            self.binnedTransportFractions[key].append(self.transportDelayFractions[i])
            self.binnedQueueFractions[key].append(self.queueDelayFractions[i])
        


        
        