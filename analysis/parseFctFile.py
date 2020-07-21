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

    def __init__(self, fctFile, numHosts, linkBw, cdfFile):
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
        self.cdfBinnedSlowdowns = {}
        self.cdfKeys = []
        for i in range(10):
            self.binnedSlowdowns[i] = []
            self.binnedAdmitFractions[i] = []
            self.binnedTransportFractions[i] = []
            self.binnedQueueFractions[i] = []
        with open(cdfFile) as f1:
            f1.readline()
            for line in f1:
                numbersStr = line.split()
                self.cdfKeys.append([int(numbersStr[0]),float(numbersStr[2])])
            print(self.cdfKeys)
        for i in range(len(self.cdfKeys)):
            self.cdfBinnedSlowdowns[i] = []
        self.parse()

    def parse(self):
        with open(self.fctFile,'r') as fctFileIn:
            for line in fctFileIn:
                numbersStr = line.split(' ')
                flowId = int(numbersStr[0])
                src = int(numbersStr[1])
                dst = int(numbersStr[2])
                msgCreationTime = float(numbersStr[6])
                msgCompletionTime = float(numbersStr[7])
                msgSchedTime = float(numbersStr[8])
                idealTime = float(numbersStr[9])
                slowdown = max(1.0, msgSchedTime / idealTime)
                msgSizeInBytes = int(numbersStr[5])
                self.msgSizes.append(msgSizeInBytes)

                # admittedTime = float(numbersStr[9])
                # firstEnqueueTime = float(numbersStr[10])

                # self.delays.append(msgSchedTime)
                # # print(numbersStr)
                # admitDelay = max(0.0,admittedTime - msgCreationTime)
                # transportDelay = max(0.0,firstEnqueueTime - admittedTime)
                # assert(msgSchedTime - admitDelay - transportDelay >= 0)
                # queueDelay = max(0.0,msgSchedTime - admitDelay - transportDelay)
                # self.qdelays.append(queueDelay)
                # self.adelays.append(admitDelay)
                # self.tdelays.append(transportDelay)
                # self.admitDelayFractions.append(admitDelay/msgSchedTime)
                # self.transportDelayFractions.append(transportDelay/msgSchedTime)
                # self.queueDelayFractions.append(queueDelay/msgSchedTime)
                # assert(queueDelay >= 0)
                # assert(admitDelay >= 0)
                # assert(transportDelay >= 0)
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
            msgSizeInPkts = msgSize/1000
            foundBin = 0
            for l in range(len(self.cdfKeys)):
                if(msgSizeInPkts <= self.cdfKeys[l][0]):
                    self.cdfBinnedSlowdowns[l].append(self.slowdowns[i])
                    foundBin = 1
                    break
            assert(foundBin == 1)
            # self.binnedAdmitFractions[key].append(self.admitDelayFractions[i])
            # self.binnedTransportFractions[key].append(self.transportDelayFractions[i])
            # self.binnedQueueFractions[key].append(self.queueDelayFractions[i])
        


        
        