#!/usr/bin/python
"""
This program scans the scaler result file (.sca) and printouts some of the
statistics on the screen.
"""

from numpy import *
from glob import glob
from optparse import OptionParser
from pprint import pprint
from functools import partial
from xml.dom import minidom
import math
import os
import random
import re
import sys
import warnings

# sys.path.insert(0, os.environ['HOME'] + 'vectio/analysis')

from parseResultFiles import *
from parseFctFile import *  

def copyExclude(source, dest, exclude):
    selectKeys = (key for key in source if key not in exclude)
    for key in selectKeys:
        if (isinstance(source[key], AttrDict)):
            dest[key] = AttrDict()
            copyExclude(source[key], dest[key], exclude)
        else:
            dest[key] = source[key]

def getStatsFromHist(bins, cumProb, idx):
    if idx == 0 and bins[idx] == -inf:
        return bins[idx + 1]
    return bins[idx]

def getInterestingModuleStats(moduleDic, statsKey, histogramKey):
    moduleStats = AttrDict()
    moduleStats = moduleStats.fromkeys(['count','min','mean','stddev','max','median','threeQuartile','ninety9Percentile'], 0.0)
    histogram = moduleDic.access(histogramKey)
    stats = moduleDic.access(statsKey)
    bins = [tuple[0] for tuple in histogram]
    if stats.count != 0:
        cumProb = cumsum([tuple[1]/stats.count for tuple in histogram])
        moduleStats.count = stats.count
        moduleStats.min = stats.min
        moduleStats.mean = stats.mean
        moduleStats.stddev = stats.stddev
        moduleStats.max = stats.max
        medianIdx = next(idx for idx,value in enumerate(cumProb) if value >= 0.5)
        moduleStats.median = max(getStatsFromHist(bins, cumProb, medianIdx), stats.min)
        threeQuartileIdx = next(idx for idx,value in enumerate(cumProb) if value >= 0.75)
        moduleStats.threeQuartile = max(getStatsFromHist(bins, cumProb, threeQuartileIdx), stats.min)
        ninety9PercentileIdx = next(idx for idx,value in enumerate(cumProb) if value >= 0.99)
        moduleStats.ninety9Percentile = max(getStatsFromHist(bins, cumProb, ninety9PercentileIdx), stats.min)
    return moduleStats

def digestModulesStats(modulesStatsList):
    statsDigest = AttrDict()
    if len(modulesStatsList) > 0:
        statsDigest = statsDigest.fromkeys(modulesStatsList[0].keys(), 0.0)
        statsDigest.min = inf
        for targetStat in modulesStatsList:
            statsDigest.count += targetStat.count
            statsDigest.min = min(targetStat.min, statsDigest.min)
            statsDigest.max = max(targetStat.max, statsDigest.max)
            statsDigest.mean += targetStat.mean * targetStat.count
            statsDigest.stddev += targetStat.stddev * targetStat.count
            statsDigest.median += targetStat.median * targetStat.count
            statsDigest.threeQuartile += targetStat.threeQuartile  * targetStat.count
            statsDigest.ninety9Percentile += targetStat.ninety9Percentile  * targetStat.count

        divideNoneZero = lambda stats, count: stats * 1.0/count if count !=0 else 0.0
        statsDigest.mean = divideNoneZero(statsDigest.mean, statsDigest.count)
        statsDigest.stddev = divideNoneZero(statsDigest.stddev, statsDigest.count)
        statsDigest.median = divideNoneZero(statsDigest.median, statsDigest.count)
        statsDigest.threeQuartile = divideNoneZero(statsDigest.threeQuartile, statsDigest.count)
        statsDigest.ninety9Percentile = divideNoneZero(statsDigest.ninety9Percentile, statsDigest.count)
    else:
        statsDigest.count = 0
        statsDigest.min = inf
        statsDigest.max = 0
        statsDigest.mean = 0
        statsDigest.stddev = 0
        statsDigest.median = 0
        statsDigest.threeQuartile = 0
        statsDigest.ninety9Percentile = 0

    return statsDigest


def hostQueueWaitTimes(hosts, xmlParsedDic, reportDigest):
    senderIds = xmlParsedDic.senderIds
    # find the queueWaitTimes for different types of packets. Current types
    # considered are request, grant and data packets. Also queueingTimes in the
    # senders NIC.
    keyStrings = ['queueingTime','unschedDataQueueingTime','schedDataQueueingTime','grantQueueingTime','requestQueueingTime']
    for keyString in keyStrings:
        queuingTimeStats = list()
        for host in hosts.keys():
            hostId = int(re.match('nic\[([0-9]+)]', host).group(1))
            queuingTimeHistogramKey = 'nic[{0}].eth[0].queue.dataQueue.{1}:histogram.bins'.format(hostId, keyString)
            queuingTimeStatsKey = 'nic[{0}].eth[0].queue.dataQueue.{1}:stats'.format(hostId,keyString)
            hostStats = AttrDict()
            if keyString != 'queueingTime' or (keyString == 'queueingTime' and hostId in senderIds):
                hostStats = getInterestingModuleStats(hosts, queuingTimeStatsKey, queuingTimeHistogramKey)
                queuingTimeStats.append(hostStats)

        queuingTimeDigest = AttrDict()
        queuingTimeDigest = digestModulesStats(queuingTimeStats)
        reportDigest.assign('queueWaitTime.hosts.{0}'.format(keyString), queuingTimeDigest)

def torsQueueWaitTime(tors, generalInfo, xmlParsedDic, reportDigest):
    numServersPerTor = int(generalInfo.numServersPerTor)
    fabricLinkSpeed = int(generalInfo.fabricLinkSpeed.strip('Gbps'))
    nicLinkSpeed = int(generalInfo.nicLinkSpeed.strip('Gbps'))
    senderHostIds = xmlParsedDic.senderIds
    senderTorIds = [elem for elem in set([int(id / numServersPerTor) for id in senderHostIds])]
    numTorUplinkNics = int(floor(numServersPerTor * nicLinkSpeed / fabricLinkSpeed))
    receiverHostIds = xmlParsedDic.receiverIds
    receiverTorIdsIfaces = [(int(id / numServersPerTor), id % numServersPerTor) for id in receiverHostIds]
    keyStrings = ['queueingTime','unschedDataQueueingTime','schedDataQueueingTime','grantQueueingTime','requestQueueingTime']
    for keyString in keyStrings:
        torsUpwardQueuingTimeStats = list()
        torsDownwardQueuingTimeStats = list()
        for torKey in tors.keys():
            torId = int(re.match('tor\[([0-9]+)]', torKey).group(1))
            tor = tors[torKey]
            # Find the queue waiting times for the upward NICs of sender tors
            # as well as the queue waiting times for various packet types.
            # For the first one we have to find torIds for all the tors
            # connected to the sender hosts
            for ifaceId in range(numServersPerTor, numServersPerTor + numTorUplinkNics):
                # Find the queuewait time only for the upward tor NICs
                queuingTimeHistogramKey = 'eth[{0}].queue.dataQueue.{1}:histogram.bins'.format(ifaceId, keyString)
                queuingTimeStatsKey = 'eth[{0}].queue.dataQueue.{1}:stats'.format(ifaceId, keyString)
                if keyString != 'queueingTime' or (keyString == 'queueingTime' and torId in senderTorIds):
                    torUpwardStat = AttrDict()
                    torUpwardStat = getInterestingModuleStats(tor, queuingTimeStatsKey, queuingTimeHistogramKey)
                    torsUpwardQueuingTimeStats.append(torUpwardStat)

            # Find the queue waiting times for the downward NICs of receiver tors
            # as well as the queue waiting times for various packet types.
            # For the first one we have to find torIds for all the tors
            # connected to the receiver hosts
            for ifaceId in range(0, numServersPerTor):
                # Find the queuewait time only for the downward tor NICs
                queuingTimeHistogramKey = 'eth[{0}].queue.dataQueue.{1}:histogram.bins'.format(ifaceId, keyString)
                queuingTimeStatsKey = 'eth[{0}].queue.dataQueue.{1}:stats'.format(ifaceId, keyString)
                if keyString != 'queueingTime' or (keyString == 'queueingTime' and (torId, ifaceId) in receiverTorIdsIfaces):
                    torDownwardStat = AttrDict()
                    torDownwardStat = getInterestingModuleStats(tor, queuingTimeStatsKey, queuingTimeHistogramKey)
                    torsDownwardQueuingTimeStats.append(torDownwardStat)

        torsUpwardQueuingTimeDigest = AttrDict()
        torsUpwardQueuingTimeDigest = digestModulesStats(torsUpwardQueuingTimeStats)
        reportDigest.assign('queueWaitTime.tors.upward.{0}'.format(keyString), torsUpwardQueuingTimeDigest)

        torsDownwardQueuingTimeDigest = AttrDict()
        torsDownwardQueuingTimeDigest = digestModulesStats(torsDownwardQueuingTimeStats)
        reportDigest.assign('queueWaitTime.tors.downward.{0}'.format(keyString), torsDownwardQueuingTimeDigest)

def aggrsQueueWaitTime(aggrs, generalInfo, xmlParsedDic, reportDigest):
    # Find the queue waiting for aggrs switches NICs
    keyStrings = ['queueingTime','unschedDataQueueingTime','schedDataQueueingTime','grantQueueingTime','requestQueueingTime']
    for keyString in keyStrings:
        aggrsQueuingTimeStats = list()
        for aggr in aggrs.keys():
            for ifaceId in range(0, int(generalInfo.numTors)):
                queuingTimeHistogramKey = '{0}.eth[{1}].queue.dataQueue.{2}:histogram.bins'.format(aggr, ifaceId,  keyString)
                queuingTimeStatsKey = '{0}.eth[{1}].queue.dataQueue.{2}:stats'.format(aggr, ifaceId, keyString)
                aggrsStats = AttrDict()
                aggrsStats = getInterestingModuleStats(aggrs, queuingTimeStatsKey, queuingTimeHistogramKey)
                aggrsQueuingTimeStats.append(aggrsStats)

        aggrsQueuingTimeDigest = AttrDict()
        aggrsQueuingTimeDigest = digestModulesStats(aggrsQueuingTimeStats)
        reportDigest.assign('queueWaitTime.aggrs.{0}'.format(keyString), aggrsQueuingTimeDigest)

def parseXmlFile(xmlConfigFile, generalInfo):
    xmlConfig = minidom.parse(xmlConfigFile)
    xmlParsedDic = AttrDict()

    senderIds = list()
    receiverIds = list()
    allHostsReceive = False
    for hostConfig in xmlConfig.getElementsByTagName('hostConfig'):
        isSender = hostConfig.getElementsByTagName('isSender')[0]
        if isSender.childNodes[0].data == 'true':
            hostId = int(hostConfig.getAttribute('id'))
            senderIds.append(hostId)
            if allHostsReceive is False:
                destIdsNode = hostConfig.getElementsByTagName('destIds')[0]
                destIds = list()
                if destIdsNode.firstChild != None:
                    destIds = [int(destId) for destId in destIdsNode.firstChild.data.split()]
                if destIds == []:
                    allHostsReceive = True
                elif -1 in destIds:
                    receiverIds += [idx for idx in range(0, int(generalInfo.numTors)*int(generalInfo.numServersPerTor)) if idx != hostId]
                else:
                    receiverIds += destIds
    xmlParsedDic.senderIds = senderIds
    if allHostsReceive is True:
        receiverIds = range(0, int(generalInfo.numTors)*int(generalInfo.numServersPerTor))
    xmlParsedDic.receiverIds = [elem for elem in set(receiverIds)]
    return xmlParsedDic

def printStatsLine(statsDic, rowTitle, tw, fw, unit, printKeys):
    if unit == 'us':
        scaleFac = 1e6
    elif unit == 'KB':
        scaleFac = 2**-10
    elif unit == '':
        scaleFac = 1

    printStr = rowTitle.ljust(tw)
    for key in printKeys:
        if key in statsDic.keys():
            if key == 'count':
                printStr += '{0}'.format(int(statsDic.access(key))).center(fw)
            elif key in ['cntPercent', 'bytesPercent']:
                printStr += '{0:.2f}'.format(statsDic.access(key)).center(fw)
            elif key == 'meanFrac':
                printStr += '{0:.2f}'.format(statsDic.access(key)).center(fw)
            elif key == 'bytes' and unit != 'KB':
                printStr += '{0:.0f}'.format(statsDic.access(key)).center(fw)
            else:
                printStr += '{0:.2f}'.format(statsDic.access(key) * scaleFac).center(fw)
    print(printStr)

def printQueueTimeStats(queueWaitTimeDigest, unit):

    printKeys = ['mean', 'meanFrac', 'stddev', 'min', 'median', 'threeQuartile', 'ninety9Percentile', 'max', 'count']
    tw = 20
    fw = 9
    lineMax = 100
    title = 'Queue Wait Time Stats'
    print('\n'*2 + ('-'*len(title)).center(lineMax,' ') + '\n' + ('|' + title + '|').center(lineMax, ' ') +
            '\n' + ('-'*len(title)).center(lineMax,' '))

    print('\n' + "Packet Type: Requst".center(lineMax,' ') + '\n' + "="*lineMax)
    print("Queue Location".ljust(tw) + 'mean'.format(unit).center(fw) + 'mean'.center(fw) + 'stddev'.format(unit).center(fw) +
            'min'.format(unit).center(fw) + 'median'.format(unit).center(fw) + '75%ile'.format(unit).center(fw) +
            '99%ile'.format(unit).center(fw) + 'max'.format(unit).center(fw) + 'count'.center(fw))
    print("".ljust(tw) + '({0})'.format(unit).center(fw) + '(%)'.center(fw) + '({0})'.format(unit).center(fw) +
            '({0})'.format(unit).center(fw) + '({0})'.format(unit).center(fw) + '({0})'.format(unit).center(fw) +
            '({0})'.format(unit).center(fw) + '({0})'.format(unit).center(fw) + ''.center(fw))

    print("_"*lineMax)
    hostStats = queueWaitTimeDigest.queueWaitTime.hosts.requestQueueingTime
    torsUpStats = queueWaitTimeDigest.queueWaitTime.tors.upward.requestQueueingTime
    torsDownStats = queueWaitTimeDigest.queueWaitTime.tors.downward.requestQueueingTime
    aggrsStats = queueWaitTimeDigest.queueWaitTime.aggrs.requestQueueingTime
    meanSum = hostStats.mean + torsUpStats.mean + torsDownStats.mean + aggrsStats.mean
    meanFracSum = 0.0
    for moduleStats in [hostStats, torsUpStats, torsDownStats, aggrsStats]:
        moduleStats.meanFrac = 0 if meanSum==0 else 100*moduleStats.mean/meanSum
        meanFracSum += moduleStats.meanFrac

    printStatsLine(hostStats, 'Host NICs:', tw, fw, unit, printKeys)
    printStatsLine(torsUpStats, 'TORs upward NICs:', tw, fw, unit, printKeys)
    printStatsLine(aggrsStats, 'Aggr Switch NICs:', tw, fw, unit, printKeys)
    printStatsLine(torsDownStats, 'TORs downward NICs:', tw, fw, unit, printKeys)
    print('_'*2*tw + '\n' + 'Total:'.ljust(tw) + '{0:.2f}'.format(meanSum*1e6).center(fw) + '{0:.2f}'.format(meanFracSum).center(fw))

    print('\n\n' + "Packet Type: Unsched. Data".center(lineMax,' ') + '\n'  + "="*lineMax)
    print("Queue Location".ljust(tw) + 'mean'.format(unit).center(fw) + 'mean'.center(fw) + 'stddev'.format(unit).center(fw) +
            'min'.format(unit).center(fw) + 'median'.format(unit).center(fw) + '75%ile'.format(unit).center(fw) +
            '99%ile'.format(unit).center(fw) + 'max'.format(unit).center(fw) + 'count'.center(fw))
    print("".ljust(tw) + '({0})'.format(unit).center(fw) + '(%)'.center(fw) + '({0})'.format(unit).center(fw) +
            '({0})'.format(unit).center(fw) + '({0})'.format(unit).center(fw) + '({0})'.format(unit).center(fw) +
            '({0})'.format(unit).center(fw) + '({0})'.format(unit).center(fw) + ''.center(fw))
    print("_"*lineMax)
    hostStats = queueWaitTimeDigest.queueWaitTime.hosts.unschedDataQueueingTime
    torsUpStats = queueWaitTimeDigest.queueWaitTime.tors.upward.unschedDataQueueingTime
    torsDownStats = queueWaitTimeDigest.queueWaitTime.tors.downward.unschedDataQueueingTime
    aggrsStats = queueWaitTimeDigest.queueWaitTime.aggrs.unschedDataQueueingTime
    if hostStats != {}:
        meanSum = hostStats.mean + torsUpStats.mean + torsDownStats.mean + aggrsStats.mean
        meanFracSum = 0.0
        for moduleStats in [hostStats, torsUpStats, torsDownStats, aggrsStats]:
            moduleStats.meanFrac = 0 if meanSum==0 else 100*moduleStats.mean/meanSum
            meanFracSum += moduleStats.meanFrac

        printStatsLine(hostStats, 'Host NICs:', tw, fw, unit, printKeys)
        printStatsLine(torsUpStats, 'TORs upward NICs:', tw, fw, unit, printKeys)
        printStatsLine(aggrsStats, 'Aggr Switch NICs:', tw, fw, unit, printKeys)
        printStatsLine(torsDownStats, 'TORs downward NICs:', tw, fw, unit, printKeys)
        print('_'*2*tw + '\n' + 'Total'.ljust(tw) + '{0:.2f}'.format(meanSum*1e6).center(fw) + '{0:.2f}'.format(meanFracSum).center(fw))


    print('\n\n' + "Packet Type: Grant".center(lineMax,' ') + '\n' + "="*lineMax)
    print("Queue Location".ljust(tw) + 'mean'.format(unit).center(fw) + 'mean'.center(fw) + 'stddev'.format(unit).center(fw) +
            'min'.format(unit).center(fw) + 'median'.format(unit).center(fw) + '75%ile'.format(unit).center(fw) +
            '99%ile'.format(unit).center(fw) + 'max'.format(unit).center(fw) + 'count'.center(fw))
    print("".ljust(tw) + '({0})'.format(unit).center(fw) + '(%)'.center(fw) + '({0})'.format(unit).center(fw) +
            '({0})'.format(unit).center(fw) + '({0})'.format(unit).center(fw) + '({0})'.format(unit).center(fw) +
            '({0})'.format(unit).center(fw) + '({0})'.format(unit).center(fw) + ''.center(fw))
    print("_"*lineMax)
    hostStats = queueWaitTimeDigest.queueWaitTime.hosts.grantQueueingTime
    torsUpStats = queueWaitTimeDigest.queueWaitTime.tors.upward.grantQueueingTime
    torsDownStats = queueWaitTimeDigest.queueWaitTime.tors.downward.grantQueueingTime
    aggrsStats = queueWaitTimeDigest.queueWaitTime.aggrs.grantQueueingTime
    meanSum = hostStats.mean + torsUpStats.mean + torsDownStats.mean + aggrsStats.mean
    meanFracSum = 0.0
    for moduleStats in [hostStats, torsUpStats, torsDownStats, aggrsStats]:
        moduleStats.meanFrac = 0 if meanSum==0 else 100*moduleStats.mean/meanSum
        meanFracSum += moduleStats.meanFrac


    printStatsLine(hostStats, 'Host NICs:', tw, fw, unit, printKeys)
    printStatsLine(torsUpStats, 'TORs upward NICs:', tw, fw, unit, printKeys)
    printStatsLine(aggrsStats, 'Aggr Switch NICs:', tw, fw, unit, printKeys)
    printStatsLine(torsDownStats, 'TORs downward NICs:', tw, fw, unit, printKeys)
    print('_'*2*tw + '\n' + 'Total:'.ljust(tw) + '{0:.2f}'.format(meanSum*1e6).center(fw) + '{0:.2f}'.format(meanFracSum).center(fw))

    print('\n\n' + "Packet Type: Sched. Data".center(lineMax,' ') + '\n'  + "="*lineMax)
    print("Queue Location".ljust(tw) + 'mean'.format(unit).center(fw) + 'mean'.center(fw) + 'stddev'.format(unit).center(fw) +
            'min'.format(unit).center(fw) + 'median'.format(unit).center(fw) + '75%ile'.format(unit).center(fw) +
            '99%ile'.format(unit).center(fw) + 'max'.format(unit).center(fw) + 'count'.center(fw))
    print("".ljust(tw) + '({0})'.format(unit).center(fw) + '(%)'.center(fw) + '({0})'.format(unit).center(fw) +
            '({0})'.format(unit).center(fw) + '({0})'.format(unit).center(fw) + '({0})'.format(unit).center(fw) +
            '({0})'.format(unit).center(fw) + '({0})'.format(unit).center(fw) + ''.center(fw))
    print("_"*lineMax)
    hostStats = queueWaitTimeDigest.queueWaitTime.hosts.schedDataQueueingTime
    torsUpStats = queueWaitTimeDigest.queueWaitTime.tors.upward.schedDataQueueingTime
    torsDownStats = queueWaitTimeDigest.queueWaitTime.tors.downward.schedDataQueueingTime
    aggrsStats = queueWaitTimeDigest.queueWaitTime.aggrs.schedDataQueueingTime
    meanSum = hostStats.mean + torsUpStats.mean + torsDownStats.mean + aggrsStats.mean
    meanFracSum = 0.0
    for moduleStats in [hostStats, torsUpStats, torsDownStats, aggrsStats]:
        moduleStats.meanFrac = 0 if meanSum==0 else 100*moduleStats.mean/meanSum
        meanFracSum += moduleStats.meanFrac

    printStatsLine(hostStats, 'Host NICs:', tw, fw, unit, printKeys)
    printStatsLine(torsUpStats, 'TORs upward NICs:', tw, fw, unit, printKeys)
    printStatsLine(aggrsStats, 'Aggr Switch NICs:', tw, fw, unit, printKeys)
    printStatsLine(torsDownStats, 'TORs downward NICs:', tw, fw, unit, printKeys)
    print('_'*2*tw + '\n' + 'Total'.ljust(tw) + '{0:.2f}'.format(meanSum*1e6).center(fw) + '{0:.2f}'.format(meanFracSum).center(fw))

    print('\n\n' + "packet Type: All Pkts".center(lineMax,' ') + '\n' + "="*lineMax)
    print("Queue Location".ljust(tw) + 'mean'.format(unit).center(fw) + 'mean'.center(fw) + 'stddev'.format(unit).center(fw) +
            'min'.format(unit).center(fw) + 'median'.format(unit).center(fw) + '75%ile'.format(unit).center(fw) +
            '99%ile'.format(unit).center(fw) + 'max'.format(unit).center(fw) + 'count'.center(fw))
    print("".ljust(tw) + '({0})'.format(unit).center(fw) + '(%)'.center(fw) + '({0})'.format(unit).center(fw) +
            '({0})'.format(unit).center(fw) + '({0})'.format(unit).center(fw) + '({0})'.format(unit).center(fw) +
            '({0})'.format(unit).center(fw) + '({0})'.format(unit).center(fw) + ''.center(fw))
    print("_"*lineMax)
    hostStats = queueWaitTimeDigest.queueWaitTime.hosts.queueingTime
    torsUpStats = queueWaitTimeDigest.queueWaitTime.tors.upward.queueingTime
    torsDownStats = queueWaitTimeDigest.queueWaitTime.tors.downward.queueingTime
    aggrsStats = queueWaitTimeDigest.queueWaitTime.aggrs.queueingTime
    meanSum = hostStats.mean + torsUpStats.mean + torsDownStats.mean + aggrsStats.mean
    meanFracSum = 0.0
    for moduleStats in [hostStats, torsUpStats, torsDownStats, aggrsStats]:
        moduleStats.meanFrac = 0 if meanSum==0 else 100*moduleStats.mean/meanSum
        meanFracSum += moduleStats.meanFrac

    printStatsLine(hostStats, 'SX Host NICs:', tw, fw, unit, printKeys)
    printStatsLine(torsUpStats, 'SX TORs UP NICs:', tw, fw, unit, printKeys)
    printStatsLine(aggrsStats, 'Aggr Switch NICs:', tw, fw, unit, printKeys)
    printStatsLine(torsDownStats, 'RX TORs Down NICs:', tw, fw, unit, printKeys)
    print('_'*2*tw + '\n' + 'Total'.ljust(tw) + '{0:.2f}'.format(meanSum*1e6).center(fw) + '{0:.2f}'.format(meanFracSum).center(fw))

def digestQueueLenInfo(queueLenDic, title):
    queueLenDigest = queueLenDic.queueLenDigest
    totalCount = sum(queueLenDic.count) * 1.0
    keyList = ['meanCnt', 'empty', 'onePkt', 'stddevCnt', 'meanBytes', 'stddevBytes']
    for key in queueLenDic.keys():
        if len(queueLenDic[key]) > 0 and key in keyList:
            queueLenDigest[key] = 0

    if totalCount != 0:
        for i,cnt in enumerate(queueLenDic.count):
            for key in queueLenDigest.keys():
                if not math.isnan(queueLenDic.access(key)[i]):
                    queueLenDigest[key] += queueLenDic.access(key)[i] * cnt

        for key in queueLenDigest.keys():
                queueLenDigest[key] /= totalCount

    for key in queueLenDic.keys():
        if len(queueLenDic[key]) == 0 and key in keyList:
            queueLenDigest[key] = nan

    queueLenDigest.title = title
    if len(queueLenDic.minCnt) > 0:
        queueLenDigest.minCnt = min(queueLenDic.minCnt)
        queueLenDigest.minBytes = min(queueLenDic.minBytes)
    if len(queueLenDic.maxCnt) > 0:
        queueLenDigest.maxCnt = max(queueLenDic.maxCnt)
        queueLenDigest.maxBytes = max(queueLenDic.maxBytes)

def computeQueueLength(parsedStats, xmlParsedDic):
    printKeys = ['meanCnt', 'stddevCnt', 'meanBytes', 'stddevBytes', 'empty', 'onePkt', 'minCnt', 'minBytes', 'maxCnt', 'maxBytes']
    queueLen = AttrDict()
    keysAll = printKeys[:]
    keysAll.append('count')
    for key in keysAll:
        queueLen.sxHosts.transport[key] = []
        queueLen.sxHosts.nic[key] = []
        queueLen.hosts.nic[key] = []
        queueLen.tors.up.nic[key] = []
        queueLen.sxTors.up.nic[key] = []
        queueLen.tors.down.nic[key] = []
        queueLen.rxTors.down.nic[key] = []
        queueLen.aggrs.nic[key] = []

    for host in parsedStats.hosts.keys():
        hostId = int(re.match('nic\[([0-9]+)]', host).group(1))
        hostStats = parsedStats.hosts[host]
        # transQueueLenCnt = hostStats.access('transportScheme.msgsLeftToSend:stats.count')
        # transQueueLenMin = hostStats.access('transportScheme.msgsLeftToSend:stats.min')
        # transQueueLenMax = hostStats.access('transportScheme.msgsLeftToSend:stats.max')
        # transQueueLenMean = hostStats.access('transportScheme.msgsLeftToSend:stats.mean')
        # transQueueLenStddev = hostStats.access('transportScheme.msgsLeftToSend:stats.stddev')
        # transQueueBytesMin = hostStats.access('transportScheme.bytesLeftToSend:stats.min')/2**10
        # transQueueBytesMax = hostStats.access('transportScheme.bytesLeftToSend:stats.max')/2**10
        # transQueueBytesMean = hostStats.access('transportScheme.bytesLeftToSend:stats.mean')/2**10
        # transQueueBytesStddev = hostStats.access('transportScheme.bytesLeftToSend:stats.stddev')/2**10

        nicQueueLenCnt = hostStats.access('eth[0].queue.dataQueue.queueLength:stats.count')
        nicQueueLenMin = hostStats.access('eth[0].queue.dataQueue.queueLength:stats.min')
        nicQueueLenEmpty = hostStats.access('eth[0].queue.dataQueue.\"queue empty (%)\".value')
        nicQueueLenOnePkt = hostStats.access('eth[0].queue.dataQueue.\"queue length one (%)\".value')
        nicQueueLenMax = hostStats.access('eth[0].queue.dataQueue.queueLength:stats.max')
        nicQueueLenMean = hostStats.access('eth[0].queue.dataQueue.queueLength:stats.mean')
        nicQueueLenStddev = hostStats.access('eth[0].queue.dataQueue.queueLength:stats.stddev')
        nicQueueBytesMin = hostStats.access('eth[0].queue.dataQueue.queueByteLength:stats.min')/2**10
        nicQueueBytesMax = hostStats.access('eth[0].queue.dataQueue.queueByteLength:stats.max')/2**10
        nicQueueBytesMean = hostStats.access('eth[0].queue.dataQueue.queueByteLength:stats.mean')/2**10
        nicQueueBytesStddev = hostStats.access('eth[0].queue.dataQueue.queueByteLength:stats.stddev')/2**10
        queueLen.hosts.nic.empty.append(nicQueueLenEmpty)
        queueLen.hosts.nic.onePkt.append(nicQueueLenOnePkt)
        queueLen.hosts.nic.count.append(nicQueueLenCnt)
        queueLen.hosts.nic.minCnt.append(nicQueueLenMin)
        queueLen.hosts.nic.maxCnt.append(nicQueueLenMax)
        queueLen.hosts.nic.meanCnt.append(nicQueueLenMean)
        queueLen.hosts.nic.stddevCnt.append(nicQueueLenStddev)
        queueLen.hosts.nic.minBytes.append(nicQueueBytesMin)
        queueLen.hosts.nic.maxBytes.append(nicQueueBytesMax)
        queueLen.hosts.nic.meanBytes.append(nicQueueBytesMean)
        queueLen.hosts.nic.stddevBytes.append(nicQueueBytesStddev)

        if hostId in xmlParsedDic.senderIds:
            # queueLen.sxHosts.transport.minCnt.append(transQueueLenMin)
            # queueLen.sxHosts.transport.count.append(transQueueLenCnt)
            # queueLen.sxHosts.transport.maxCnt.append(transQueueLenMax)
            # queueLen.sxHosts.transport.meanCnt.append(transQueueLenMean)
            # queueLen.sxHosts.transport.stddevCnt.append(transQueueLenStddev)
            # queueLen.sxHosts.transport.minBytes.append(transQueueBytesMin)
            # queueLen.sxHosts.transport.maxBytes.append(transQueueBytesMax)
            # queueLen.sxHosts.transport.meanBytes.append(transQueueBytesMean)
            # queueLen.sxHosts.transport.stddevBytes.append(transQueueBytesStddev)

            queueLen.sxHosts.nic.minCnt.append(nicQueueLenMin)
            queueLen.sxHosts.nic.count.append(nicQueueLenCnt)
            queueLen.sxHosts.nic.empty.append(nicQueueLenEmpty)
            queueLen.sxHosts.nic.onePkt.append(nicQueueLenOnePkt)
            queueLen.sxHosts.nic.maxCnt.append(nicQueueLenMax)
            queueLen.sxHosts.nic.meanCnt.append(nicQueueLenMean)
            queueLen.sxHosts.nic.stddevCnt.append(nicQueueLenStddev)
            queueLen.sxHosts.nic.minBytes.append(nicQueueBytesMin)
            queueLen.sxHosts.nic.maxBytes.append(nicQueueBytesMax)
            queueLen.sxHosts.nic.meanBytes.append(nicQueueBytesMean)
            queueLen.sxHosts.nic.stddevBytes.append(nicQueueBytesStddev)

    numServersPerTor = int(parsedStats.generalInfo.numServersPerTor)
    fabricLinkSpeed = int(parsedStats.generalInfo.fabricLinkSpeed.strip('Gbps'))
    nicLinkSpeed = int(parsedStats.generalInfo.nicLinkSpeed.strip('Gbps'))
    numTorUplinkNics = int(floor(numServersPerTor * nicLinkSpeed / fabricLinkSpeed))
    senderHostIds = xmlParsedDic.senderIds
    senderTorIds = [elem for elem in set([int(id / numServersPerTor) for id in senderHostIds])]
    receiverHostIds = xmlParsedDic.receiverIds
    receiverTorIdsIfaces = [(int(id / numServersPerTor), id % numServersPerTor) for id in receiverHostIds]

    for torKey in parsedStats.tors.keys():
        tor = parsedStats.tors[torKey]
        torId = int(re.match('tor\[([0-9]+)]', torKey).group(1))
        for ifaceId in range(0, numServersPerTor + numTorUplinkNics):
            nicQueueLenEmpty = tor.access('eth[{0}].queue.dataQueue.\"queue empty (%)\".value'.format(ifaceId))
            nicQueueLenOnePkt = tor.access('eth[{0}].queue.dataQueue.\"queue length one (%)\".value'.format(ifaceId))
            nicQueueLenMin = tor.access('eth[{0}].queue.dataQueue.queueLength:stats.min'.format(ifaceId))
            nicQueueLenCnt = tor.access('eth[{0}].queue.dataQueue.queueLength:stats.count'.format(ifaceId))
            nicQueueLenMax = tor.access('eth[{0}].queue.dataQueue.queueLength:stats.max'.format(ifaceId))
            nicQueueLenMean = tor.access('eth[{0}].queue.dataQueue.queueLength:stats.mean'.format(ifaceId))
            nicQueueLenStddev = tor.access('eth[{0}].queue.dataQueue.queueLength:stats.stddev'.format(ifaceId))
            nicQueueBytesMin = tor.access('eth[{0}].queue.dataQueue.queueByteLength:stats.min'.format(ifaceId))/2**10
            nicQueueBytesMax = tor.access('eth[{0}].queue.dataQueue.queueByteLength:stats.max'.format(ifaceId))/2**10
            nicQueueBytesMean = tor.access('eth[{0}].queue.dataQueue.queueByteLength:stats.mean'.format(ifaceId))/2**10
            nicQueueBytesStddev = tor.access('eth[{0}].queue.dataQueue.queueByteLength:stats.stddev'.format(ifaceId))/2**10

            if ifaceId < numServersPerTor:
                queueLen.tors.down.nic.minCnt.append(nicQueueLenMin)
                queueLen.tors.down.nic.count.append(nicQueueLenCnt)
                queueLen.tors.down.nic.empty.append(nicQueueLenEmpty)
                queueLen.tors.down.nic.onePkt.append(nicQueueLenOnePkt)
                queueLen.tors.down.nic.maxCnt.append(nicQueueLenMax)
                queueLen.tors.down.nic.meanCnt.append(nicQueueLenMean)
                queueLen.tors.down.nic.stddevCnt.append(nicQueueLenStddev)
                queueLen.tors.down.nic.minBytes.append(nicQueueBytesMin)
                queueLen.tors.down.nic.maxBytes.append(nicQueueBytesMax)
                queueLen.tors.down.nic.meanBytes.append(nicQueueBytesMean)
                queueLen.tors.down.nic.stddevBytes.append(nicQueueBytesStddev)

                if (torId, ifaceId) in receiverTorIdsIfaces:
                    queueLen.rxTors.down.nic.minCnt.append(nicQueueLenMin)
                    queueLen.rxTors.down.nic.count.append(nicQueueLenCnt)
                    queueLen.rxTors.down.nic.empty.append(nicQueueLenEmpty)
                    queueLen.rxTors.down.nic.onePkt.append(nicQueueLenOnePkt)
                    queueLen.rxTors.down.nic.maxCnt.append(nicQueueLenMax)
                    queueLen.rxTors.down.nic.meanCnt.append(nicQueueLenMean)
                    queueLen.rxTors.down.nic.stddevCnt.append(nicQueueLenStddev)
                    queueLen.rxTors.down.nic.minBytes.append(nicQueueBytesMin)
                    queueLen.rxTors.down.nic.maxBytes.append(nicQueueBytesMax)
                    queueLen.rxTors.down.nic.meanBytes.append(nicQueueBytesMean)
                    queueLen.rxTors.down.nic.stddevBytes.append(nicQueueBytesStddev)

            else:
                queueLen.tors.up.nic.minCnt.append(nicQueueLenMin)
                queueLen.tors.up.nic.count.append(nicQueueLenCnt)
                queueLen.tors.up.nic.empty.append(nicQueueLenEmpty)
                queueLen.tors.up.nic.onePkt.append(nicQueueLenOnePkt)
                queueLen.tors.up.nic.maxCnt.append(nicQueueLenMax)
                queueLen.tors.up.nic.meanCnt.append(nicQueueLenMean)
                queueLen.tors.up.nic.stddevCnt.append(nicQueueLenStddev)
                queueLen.tors.up.nic.minBytes.append(nicQueueBytesMin)
                queueLen.tors.up.nic.maxBytes.append(nicQueueBytesMax)
                queueLen.tors.up.nic.meanBytes.append(nicQueueBytesMean)
                queueLen.tors.up.nic.stddevBytes.append(nicQueueBytesStddev)

                if torId in senderTorIds:
                    queueLen.sxTors.up.nic.minCnt.append(nicQueueLenMin)
                    queueLen.sxTors.up.nic.count.append(nicQueueLenCnt)
                    queueLen.sxTors.up.nic.empty.append(nicQueueLenEmpty)
                    queueLen.sxTors.up.nic.onePkt.append(nicQueueLenOnePkt)
                    queueLen.sxTors.up.nic.maxCnt.append(nicQueueLenMax)
                    queueLen.sxTors.up.nic.meanCnt.append(nicQueueLenMean)
                    queueLen.sxTors.up.nic.stddevCnt.append(nicQueueLenStddev)
                    queueLen.sxTors.up.nic.minBytes.append(nicQueueBytesMin)
                    queueLen.sxTors.up.nic.maxBytes.append(nicQueueBytesMax)
                    queueLen.sxTors.up.nic.meanBytes.append(nicQueueBytesMean)
                    queueLen.sxTors.up.nic.stddevBytes.append(nicQueueBytesStddev)

    for aggrKey in parsedStats.aggrs.keys():
        aggr = parsedStats.aggrs[aggrKey]
        aggrId = int(re.match('aggRouter\[([0-9]+)]', aggrKey).group(1))
        for ifaceId in range(0, int(parsedStats.generalInfo.numTors)):
            nicQueueLenEmpty = aggr.access('eth[{0}].queue.dataQueue.\"queue empty (%)\".value'.format(ifaceId))
            nicQueueLenOnePkt = aggr.access('eth[{0}].queue.dataQueue.\"queue length one (%)\".value'.format(ifaceId))
            nicQueueLenMin = aggr.access('eth[{0}].queue.dataQueue.queueLength:stats.min'.format(ifaceId))
            nicQueueLenCnt = aggr.access('eth[{0}].queue.dataQueue.queueLength:stats.count'.format(ifaceId))
            nicQueueLenMax = aggr.access('eth[{0}].queue.dataQueue.queueLength:stats.max'.format(ifaceId))
            nicQueueLenMean = aggr.access('eth[{0}].queue.dataQueue.queueLength:stats.mean'.format(ifaceId))
            nicQueueLenStddev = aggr.access('eth[{0}].queue.dataQueue.queueLength:stats.stddev'.format(ifaceId))
            nicQueueBytesMin = aggr.access('eth[{0}].queue.dataQueue.queueByteLength:stats.min'.format(ifaceId))/2**10
            nicQueueBytesMax = aggr.access('eth[{0}].queue.dataQueue.queueByteLength:stats.max'.format(ifaceId))/2**10
            nicQueueBytesMean = aggr.access('eth[{0}].queue.dataQueue.queueByteLength:stats.mean'.format(ifaceId))/2**10
            nicQueueBytesStddev = aggr.access('eth[{0}].queue.dataQueue.queueByteLength:stats.stddev'.format(ifaceId))/2**10

            queueLen.aggrs.nic.minCnt.append(nicQueueLenMin)
            queueLen.aggrs.nic.count.append(nicQueueLenCnt)
            queueLen.aggrs.nic.empty.append(nicQueueLenEmpty)
            queueLen.aggrs.nic.onePkt.append(nicQueueLenOnePkt)
            queueLen.aggrs.nic.maxCnt.append(nicQueueLenMax)
            queueLen.aggrs.nic.meanCnt.append(nicQueueLenMean)
            queueLen.aggrs.nic.stddevCnt.append(nicQueueLenStddev)
            queueLen.aggrs.nic.minBytes.append(nicQueueBytesMin)
            queueLen.aggrs.nic.maxBytes.append(nicQueueBytesMax)
            queueLen.aggrs.nic.meanBytes.append(nicQueueBytesMean)
            queueLen.aggrs.nic.stddevBytes.append(nicQueueBytesStddev)

    # digestQueueLenInfo(queueLen.sxHosts.transport, 'SX Transports')
    digestQueueLenInfo(queueLen.sxHosts.nic, 'SX NICs')
    digestQueueLenInfo(queueLen.hosts.nic, 'All NICs')
    digestQueueLenInfo(queueLen.sxTors.up.nic, 'SX TORs Up')
    digestQueueLenInfo(queueLen.tors.up.nic, 'All TORs Up')
    digestQueueLenInfo(queueLen.rxTors.down.nic, 'RX TORs Down')
    digestQueueLenInfo(queueLen.tors.down.nic, 'All TORs Down')
    digestQueueLenInfo(queueLen.aggrs.nic, 'All AGGRs')
    return  queueLen

def printQueueLength(queueLen):
    printKeys = ['meanCnt', 'stddevCnt', 'meanBytes', 'stddevBytes', 'empty', 'onePkt', 'minCnt', 'minBytes', 'maxCnt', 'maxBytes']
    tw = 15
    fw = 9
    lineMax = 105
    title = 'Queue Length (Stats Collected At Pkt Arrivals)'
    print('\n'*2 + ('-'*len(title)).center(lineMax,' ') + '\n' + ('|' + title + '|').center(lineMax, ' ') +
            '\n' + ('-'*len(title)).center(lineMax,' '))
    print("="*lineMax)
    print("Queue Location".ljust(tw) + 'Mean'.center(fw) + 'StdDev'.center(fw) + 'Mean'.center(fw) + 'StdDev'.center(fw) +
             'Empty'.center(fw) + 'OnePkt'.center(fw) + 'Min'.center(fw) + 'Min'.center(fw) + 'Max'.center(fw) + 'Max'.center(fw))
    print("".ljust(tw) + '(Pkts)'.center(fw) + '(Pkts)'.center(fw) + '(KB)'.center(fw) + '(KB)'.center(fw) +
             '%'.center(fw) + '%'.center(fw) + '(Pkts)'.center(fw) + '(KB)'.center(fw) + '(Pkts)'.center(fw) + '(KB)'.center(fw))
    print("_"*lineMax)

    # printStatsLine(queueLen.sxHosts.transport.queueLenDigest, queueLen.sxHosts.transport.queueLenDigest.title, tw, fw, '', printKeys)
    printStatsLine(queueLen.sxHosts.nic.queueLenDigest, queueLen.sxHosts.nic.queueLenDigest.title, tw, fw, '', printKeys)
    printStatsLine(queueLen.hosts.nic.queueLenDigest, queueLen.hosts.nic.queueLenDigest.title, tw, fw, '', printKeys)
    printStatsLine(queueLen.sxTors.up.nic.queueLenDigest, queueLen.sxTors.up.nic.queueLenDigest.title, tw, fw, '', printKeys)
    printStatsLine(queueLen.tors.up.nic.queueLenDigest, queueLen.tors.up.nic.queueLenDigest.title, tw, fw, '', printKeys)
    printStatsLine(queueLen.aggrs.nic.queueLenDigest, queueLen.aggrs.nic.queueLenDigest.title, tw, fw, '', printKeys)
    printStatsLine(queueLen.rxTors.down.nic.queueLenDigest, queueLen.rxTors.down.nic.queueLenDigest.title, tw, fw, '', printKeys)
    printStatsLine(queueLen.tors.down.nic.queueLenDigest, queueLen.tors.down.nic.queueLenDigest.title, tw, fw, '', printKeys)

def printGenralInfo(xmlParsedDic, generalInfo):
    tw = 20
    fw = 12
    lineMax = 100
    title = 'General Simulation Information'
    print('\n'*2 + ('-'*len(title)).center(lineMax,' ') + '\n' + ('|' + title + '|').center(lineMax, ' ') +
            '\n' + ('-'*len(title)).center(lineMax,' '))
    print('Servers Per TOR:'.ljust(tw) + '{0}'.format(generalInfo.numServersPerTor).center(fw) + 'Sender Hosts:'.ljust(tw) +
        '{0}'.format(len(xmlParsedDic.senderIds)).center(fw) + 'Load Factor:'.ljust(tw) + '{0}'.format('%'+str((float(generalInfo.rlf)*100))).center(fw))
    print('TORs:'.ljust(tw) + '{0}'.format(generalInfo.numTors).center(fw) + 'Receiver Hosts:'.ljust(tw) + '{0}'.format(len(xmlParsedDic.receiverIds)).center(fw)
        + 'Start Time:'.ljust(tw) + '{0}'.format(generalInfo.startTime).center(fw))
    print('Host Link Speed:'.ljust(tw) + '{0}'.format(generalInfo.nicLinkSpeed).center(fw) + 'InterArrival Dist:'.ljust(tw) +
        '{0}'.format(generalInfo.interArrivalDist).center(fw) + 'Stop Time:'.ljust(tw) + '{0}'.format(generalInfo.stopTime).center(fw))
    print('Fabric Link Speed:'.ljust(tw) + '{0}'.format(generalInfo.fabricLinkSpeed).center(fw) + 'Edge Link Delay'.ljust(tw) +
        '{0}'.format(generalInfo.edgeLinkDelay).center(fw) + 'Switch Fix Delay:'.ljust(tw) + '{0}'.format(generalInfo.switchFixDelay).center(fw))
    print('Fabric Link Delay'.ljust(tw) + '{0}'.format(generalInfo.fabricLinkDelay).center(fw) + 'SW Turnaround Time:'.ljust(tw) +
        '{0}'.format(generalInfo.hostSwTurnAroundTime).center(fw) + 'NIC Sx ThinkTime:'.ljust(tw) + '{0}'.format(generalInfo.hostNicSxThinkTime).center(fw))
    print('TransportScheme:'.ljust(tw) + '{0} '.format(generalInfo.transportSchemeType).center(fw) + 'Workload Type:'.ljust(tw) +
        '{0}'.format(generalInfo.workloadType).center(fw))

def computeBytesAndRates(parsedStats, xmlParsedDic):
    trafficDic = AttrDict()
    txAppsBytes = trafficDic.sxHostsTraffic.apps.sx.bytes = []
    txAppsRates = trafficDic.sxHostsTraffic.apps.sx.rates = []
    rxAppsBytes = trafficDic.rxHostsTraffic.apps.rx.bytes = []
    rxAppsRates = trafficDic.rxHostsTraffic.apps.rx.rates = []
    txNicsBytes = trafficDic.sxHostsTraffic.nics.sx.bytes = []
    txNicsRates = trafficDic.sxHostsTraffic.nics.sx.rates = []
    txNicsDutyCycles = trafficDic.sxHostsTraffic.nics.sx.dutyCycles = []
    rxNicsBytes = trafficDic.rxHostsTraffic.nics.rx.bytes = []
    rxNicsRates = trafficDic.rxHostsTraffic.nics.rx.rates = []
    rxNicsDutyCycles = trafficDic.rxHostsTraffic.nics.rx.dutyCycles = []

    nicTxBytes = trafficDic.hostsTraffic.nics.sx.bytes = []
    nicTxRates = trafficDic.hostsTraffic.nics.sx.rates = []
    nicTxDutyCycles = trafficDic.hostsTraffic.nics.sx.dutyCycles = []
    nicRxBytes = trafficDic.hostsTraffic.nics.rx.bytes = []
    nicRxRates = trafficDic.hostsTraffic.nics.rx.rates = []
    nicRxDutyCycles = trafficDic.hostsTraffic.nics.rx.dutyCycles = []

    ethInterArrivalGapBit = 12*8.0 + 8.0*8
    for host in parsedStats.hosts.keys():
        hostId = int(re.match('nic\[([0-9]+)]', host).group(1))
        hostStats = parsedStats.hosts[host]
        nicSendBytes = hostStats.access('eth[0].mac.txPk:sum(packetBytes).value')
        nicSendRate = hostStats.access('eth[0].mac.\"bits/sec sent\".value')/1e9
        # Include the 12Bytes ethernet inter arrival gap in the bit rate
        nicSendRate += (hostStats.access('eth[0].mac.\"frames/sec sent\".value') * ethInterArrivalGapBit / 1e9)
        nicSendDutyCycle = hostStats.access('eth[0].mac.\"tx channel utilization (%)\".value')
        nicRcvBytes = hostStats.access('eth[0].mac.rxPkOk:sum(packetBytes).value')
        nicRcvRate = hostStats.access('eth[0].mac.\"bits/sec rcvd\".value')/1e9
        # Include the 12Bytes ethernet inter arrival gap in the bit rate
        nicRcvRate += (hostStats.access('eth[0].mac.\"frames/sec rcvd\".value') * ethInterArrivalGapBit / 1e9)
        nicRcvDutyCycle = hostStats.access('eth[0].mac.\"rx channel utilization (%)\".value')
        nicTxBytes.append(nicSendBytes)
        nicTxRates.append(nicSendRate)
        nicTxDutyCycles.append(nicSendDutyCycle)
        nicRxBytes.append(nicRcvBytes)
        nicRxRates.append(nicRcvRate)
        nicRxDutyCycles.append(nicRcvDutyCycle)

        if hostId in xmlParsedDic.senderIds:
            # txAppsBytes.append(hostStats.access('trafficGeneratorApp[0].sentMsg:sum(packetBytes).value'))
            # txAppsRates.append(hostStats.access('trafficGeneratorApp[0].sentMsg:last(sumPerDuration(packetBytes)).value')*8.0/1e9)
            txNicsBytes.append(nicSendBytes)
            txNicsRates.append(nicSendRate)
            txNicsDutyCycles.append(nicSendDutyCycle)
        if hostId in xmlParsedDic.receiverIds:
            # rxAppsBytes.append(hostStats.access('trafficGeneratorApp[0].rcvdMsg:sum(packetBytes).value'))
            # rxAppsRates.append(hostStats.access('trafficGeneratorApp[0].rcvdMsg:last(sumPerDuration(packetBytes)).value')*8.0/1e9)
            rxNicsBytes.append(nicRcvBytes)
            rxNicsRates.append(nicRcvRate)
            rxNicsDutyCycles.append(nicRcvDutyCycle)

    upNicsTxBytes = trafficDic.torsTraffic.upNics.sx.bytes = []
    upNicsTxRates = trafficDic.torsTraffic.upNics.sx.rates = []
    upNicsTxDutyCycle = trafficDic.torsTraffic.upNics.sx.dutyCycles = []
    upNicsRxBytes = trafficDic.torsTraffic.upNics.rx.bytes = []
    upNicsRxRates = trafficDic.torsTraffic.upNics.rx.rates = []
    upNicsRxDutyCycle = trafficDic.torsTraffic.upNics.rx.dutyCycles = []
    downNicsTxBytes =  trafficDic.torsTraffic.downNics.sx.bytes = []
    downNicsTxRates =  trafficDic.torsTraffic.downNics.sx.rates = []
    downNicsTxDutyCycle = trafficDic.torsTraffic.downNics.sx.dutyCycles = []
    downNicsRxBytes = trafficDic.torsTraffic.downNics.rx.bytes = []
    downNicsRxRates = trafficDic.torsTraffic.downNics.rx.rates = []
    downNicsRxDutyCycle = trafficDic.torsTraffic.downNics.rx.dutyCycles = []

    numServersPerTor = int(parsedStats.generalInfo.numServersPerTor)
    fabricLinkSpeed = int(parsedStats.generalInfo.fabricLinkSpeed.strip('Gbps'))
    nicLinkSpeed = int(parsedStats.generalInfo.nicLinkSpeed.strip('Gbps'))
    numTorUplinkNics = int(floor(numServersPerTor * nicLinkSpeed / fabricLinkSpeed))
    for torKey in parsedStats.tors.keys():
        tor = parsedStats.tors[torKey]
        for ifaceId in range(0, numServersPerTor + numTorUplinkNics):
            nicRecvBytes = tor.access('eth[{0}].mac.rxPkOk:sum(packetBytes).value'.format(ifaceId))
            nicRecvRates = tor.access('eth[{0}].mac.\"bits/sec rcvd\".value'.format(ifaceId))/1e9
            # Include the 12Bytes ethernet inter arrival gap in the bit rate
            nicRecvRates += (tor.access('eth[{0}].mac.\"frames/sec rcvd\".value'.format(ifaceId)) * ethInterArrivalGapBit / 1e9)
            nicRecvDutyCycle = tor.access('eth[{0}].mac.\"rx channel utilization (%)\".value'.format(ifaceId))
            nicSendBytes = tor.access('eth[{0}].mac.txPk:sum(packetBytes).value'.format(ifaceId))
            nicSendRates = tor.access('eth[{0}].mac.\"bits/sec sent\".value'.format(ifaceId))/1e9
            # Include the 12Bytes ethernet inter arrival gap in the bit rate
            nicSendRates += (tor.access('eth[{0}].mac.\"frames/sec sent\".value'.format(ifaceId)) * ethInterArrivalGapBit / 1e9)
            nicSendDutyCycle = tor.access('eth[{0}].mac.\"tx channel utilization (%)\".value'.format(ifaceId))
            if ifaceId < numServersPerTor:
                downNicsRxBytes.append(nicRecvBytes)
                downNicsRxRates.append(nicRecvRates)
                downNicsRxDutyCycle.append(nicRecvDutyCycle)
                downNicsTxBytes.append(nicSendBytes)
                downNicsTxRates.append(nicSendRates)
                downNicsTxDutyCycle.append(nicSendDutyCycle)
            else :
                upNicsRxBytes.append(nicRecvBytes)
                upNicsRxRates.append(nicRecvRates)
                upNicsRxDutyCycle.append(nicRecvDutyCycle)
                upNicsTxBytes.append(nicSendBytes)
                upNicsTxRates.append(nicSendRates)
                upNicsTxDutyCycle.append(nicSendDutyCycle)
    return trafficDic

def printBytesAndRates(trafficDic):
    printKeys = ['avgRate', 'cumRate', 'minRate', 'maxRate', 'cumBytes', 'avgDutyCycle', 'minDutyCycle', 'maxDutyCycle']
    tw = 15
    fw = 10
    lineMax = 100
    title = 'Traffic Characteristic (Rates, Bytes, and DutyCycle)'
    print('\n'*2 + ('-'*len(title)).center(lineMax,' ') + '\n' + ('|' + title + '|').center(lineMax, ' ') +
            '\n' + ('-'*len(title)).center(lineMax,' '))

    print("="*lineMax)
    print("Measurement".ljust(tw) + 'AvgRate'.center(fw) + 'CumRate'.center(fw) + 'MinRate'.center(fw) + 'MaxRate'.center(fw) +
             'CumBytes'.center(fw) + 'Avg Duty'.center(fw) + 'Min Duty'.center(fw) + 'Max Duty'.center(fw))
    print("Point".ljust(tw) + '(Gb/s)'.center(fw) + '(Gb/s)'.center(fw) + '(Gb/s)'.center(fw) + '(Gb/s)'.center(fw) +
            '(MB)'.center(fw) + 'Cycle(%)'.center(fw) + 'Cycle(%)'.center(fw) + 'Cycle(%)'.center(fw))

    print("_"*lineMax)
    # digestTrafficInfo(trafficDic.sxHostsTraffic.apps.sx, 'SX Apps Send:')
    # printStatsLine(trafficDic.sxHostsTraffic.apps.sx.trafficDigest, trafficDic.sxHostsTraffic.apps.sx.trafficDigest.title, tw, fw, '', printKeys)
    digestTrafficInfo(trafficDic.sxHostsTraffic.nics.sx, 'SX NICs Send:')
    printStatsLine(trafficDic.sxHostsTraffic.nics.sx.trafficDigest, trafficDic.sxHostsTraffic.nics.sx.trafficDigest.title, tw, fw, '', printKeys)
    digestTrafficInfo(trafficDic.hostsTraffic.nics.sx, 'All NICs Send:')
    printStatsLine(trafficDic.hostsTraffic.nics.sx.trafficDigest, trafficDic.hostsTraffic.nics.sx.trafficDigest.title, tw, fw, '', printKeys)


    digestTrafficInfo(trafficDic.torsTraffic.downNics.rx, 'TORs Down Recv:')
    printStatsLine(trafficDic.torsTraffic.downNics.rx.trafficDigest, trafficDic.torsTraffic.downNics.rx.trafficDigest.title, tw, fw, '', printKeys)
    digestTrafficInfo(trafficDic.torsTraffic.upNics.sx, 'TORs Up Send:')
    printStatsLine(trafficDic.torsTraffic.upNics.sx.trafficDigest, trafficDic.torsTraffic.upNics.sx.trafficDigest.title, tw, fw, '', printKeys)
    digestTrafficInfo(trafficDic.torsTraffic.upNics.rx, 'TORs Up Recv:')
    printStatsLine(trafficDic.torsTraffic.upNics.rx.trafficDigest, trafficDic.torsTraffic.upNics.rx.trafficDigest.title, tw, fw, '', printKeys)
    digestTrafficInfo(trafficDic.torsTraffic.downNics.sx, 'TORs Down Send:')
    printStatsLine(trafficDic.torsTraffic.downNics.sx.trafficDigest, trafficDic.torsTraffic.downNics.sx.trafficDigest.title, tw, fw, '', printKeys)


    digestTrafficInfo(trafficDic.hostsTraffic.nics.rx, 'ALL NICs Recv:')
    printStatsLine(trafficDic.hostsTraffic.nics.rx.trafficDigest, trafficDic.hostsTraffic.nics.rx.trafficDigest.title, tw, fw, '', printKeys)
    digestTrafficInfo(trafficDic.rxHostsTraffic.nics.rx, 'RX NICs Recv:')
    printStatsLine(trafficDic.rxHostsTraffic.nics.rx.trafficDigest, trafficDic.rxHostsTraffic.nics.rx.trafficDigest.title, tw, fw, '', printKeys)
    # digestTrafficInfo(trafficDic.rxHostsTraffic.apps.rx, 'RX Apps Recv:')
    # printStatsLine(trafficDic.rxHostsTraffic.apps.rx.trafficDigest, trafficDic.rxHostsTraffic.apps.rx.trafficDigest.title, tw, fw, '', printKeys)

def digestTrafficInfo(trafficBytesAndRateDic, title):
    trafficDigest = trafficBytesAndRateDic.trafficDigest
    trafficDigest.title = title
    if 'bytes' in trafficBytesAndRateDic.keys() and len(trafficBytesAndRateDic.bytes) > 0:
        trafficDigest.cumBytes = sum(trafficBytesAndRateDic.bytes)/1e6
    if 'rates' in trafficBytesAndRateDic.keys() and len(trafficBytesAndRateDic.rates) > 0:
        trafficDigest.cumRate = sum(trafficBytesAndRateDic.rates)
        trafficDigest.avgRate = trafficDigest.cumRate/float(len(trafficBytesAndRateDic.rates))
        trafficDigest.minRate = min(trafficBytesAndRateDic.rates)
        trafficDigest.maxRate = max(trafficBytesAndRateDic.rates)
    if 'dutyCycles' in trafficBytesAndRateDic.keys() and len(trafficBytesAndRateDic.dutyCycles) > 0:
        trafficDigest.avgDutyCycle = sum(trafficBytesAndRateDic.dutyCycles)/float(len(trafficBytesAndRateDic.dutyCycles))
        trafficDigest.minDutyCycle = min(trafficBytesAndRateDic.dutyCycles)
        trafficDigest.maxDutyCycle = max(trafficBytesAndRateDic.dutyCycles)

def main():
    parser = OptionParser()
    options, args = parser.parse_args()
    if len(args) > 0:
        scalarResultFile = args[0]
    else:
        scalarResultFile = '../homatransport/src/dcntopo/results/VectioSender/InFileDist-2.sca'

    if len(args) > 1:
        xmlConfigFile = args[1]
    else:
        xmlConfigFile = '../homatransport/src/dcntopo/config.xml'

    if len(args) > 2:
        fctFile = args[2]
    else:
        fctFile = '../homatransport/src/dcntopo/results/fcts-sdr.txt'
    print(scalarResultFile)
    print(fctFile)

    # sp = ScalarParser(scalarResultFile)
    # parsedStats = AttrDict()
    # parsedStats.hosts = sp.hosts
    # parsedStats.tors = sp.tors
    # parsedStats.aggrs = sp.aggrs
    # parsedStats.cores = sp.cores
    # parsedStats.generalInfo = sp.generalInfo
    # parsedStats.globalListener = sp.globalListener

    # xmlParsedDic = AttrDict()
    # xmlParsedDic = parseXmlFile(xmlConfigFile, parsedStats.generalInfo)

    # queueWaitTimeDigest = AttrDict()
    # hostQueueWaitTimes(parsedStats.hosts, xmlParsedDic, queueWaitTimeDigest)
    # torsQueueWaitTime(parsedStats.tors, parsedStats.generalInfo, xmlParsedDic, queueWaitTimeDigest)
    # aggrsQueueWaitTime(parsedStats.aggrs, parsedStats.generalInfo, xmlParsedDic, queueWaitTimeDigest)
    # # printGenralInfo(xmlParsedDic, parsedStats.generalInfo)
    # trafficDic = computeBytesAndRates(parsedStats, xmlParsedDic)
    # printBytesAndRates(trafficDic)

    # queueLen = computeQueueLength(parsedStats, xmlParsedDic)
    # printQueueLength(queueLen)
    # printQueueTimeStats(queueWaitTimeDigest, 'us')

    fcts = FctParser(fctFile, 144, 100e9, '../../workload_generator/CDF_aditya.txt')
    print("Throughput: mean: ", sum(fcts.throughputs)/len(fcts.throughputs), " median: ", percentile(fcts.throughputs,50), " 99%: ", percentile(fcts.throughputs,99))
    print("Inloads: mean: ", sum(fcts.inloads)/len(fcts.inloads), " median: ", percentile(fcts.inloads,50), " 99%: ", percentile(fcts.inloads,99))
    # print("Throughputs: ", fcts.throughputs)
    # print("Inloads: ", fcts.inloads)
    # print(fcts.senderStartSendingTime)
    # print(fcts.senderStopSendingTime)
    print("Mean slowdown: ", sum(fcts.slowdowns)/len(fcts.slowdowns))
    print("90 slowdown: ", percentile(fcts.slowdowns,90))
    print("99 slowdown: ", percentile(fcts.slowdowns,99))
    print("Max slowdown: ", max(fcts.slowdowns))

    print("Max index: ", fcts.slowdowns.index(max(fcts.slowdowns)))
    print("No of msgs: ", len(fcts.slowdowns))

    count = 0
    for i in range(len(fcts.slowdowns)):
        if(fcts.slowdowns[i] > 20):
            count += 1
            # print("Check row: ", i+1, " slowdown: ", fcts.slowdowns[i])
    print("No of bad slowdowns: ", count)

    print("Printing binned slowdowns")
    for i in range(len(fcts.binnedSlowdowns)):
        minSize = 10**i
        maxSize = ((10**(i+1)) - 1)
        slowdowns = fcts.binnedSlowdowns[i]
        if(len(slowdowns) > 0):
            print("Range(B): ", minSize, " - ", maxSize, ": num msgs: ", len(slowdowns), " mean slowdown: ", sum(slowdowns)/len(slowdowns), " 90%: ", percentile(slowdowns,90), " 99%: ", percentile(slowdowns,99), " max: ", max(slowdowns))
        else:
            print("Range(B): ", minSize, " - ", maxSize, ": num msgs: ", len(slowdowns))

    print("Printing binned cdf slowdowns")
    for i in range(len(fcts.cdfBinnedSlowdowns)):
        pktSize = fcts.cdfKeys[i][0]
        slowdowns = fcts.cdfBinnedSlowdowns[i]
        if(len(slowdowns) > 0):
            print("Range(B): ", pktSize, " - ", fcts.cdfKeys[i][1], ": num msgs: ", len(slowdowns), " mean slowdown: ", sum(slowdowns)/len(slowdowns), " 90%: ", percentile(slowdowns,90), " 99%: ", percentile(slowdowns,99), " max: ", max(slowdowns))
        else:
            print("Range(B): ", pktSize, " - ", fcts.cdfKeys[i][1], ": num msgs: ", len(slowdowns))

    # print("Printing delay fractions")
    # for i in range(len(fcts.binnedAdmitFractions)):
    #     minSize = 10**i
    #     maxSize = ((10**(i+1)) - 1)
    #     admitFractions = fcts.binnedAdmitFractions[i]
    #     transportFractions = fcts.binnedTransportFractions[i]
    #     queueFractions = fcts.binnedQueueFractions[i]
    #     if(len(admitFractions) > 0):
    #         print("Range(B): ", minSize, " - ", maxSize, ": num msgs: ", len(admitFractions), " mean admitF: ", sum(admitFractions)/len(admitFractions), " 90%: ", percentile(admitFractions,90), " 99%: ", percentile(admitFractions,99), "max: ", max(admitFractions), " mean transportF: ", sum(transportFractions)/len(transportFractions), " 90%: ", percentile(transportFractions,90), " 99%: ", percentile(transportFractions,99), "max: ", max(transportFractions), " mean queueF: ", sum(queueFractions)/len(queueFractions), " 90%: ", percentile(queueFractions,90), " 99%: ", percentile(queueFractions,99), "max: ", max(queueFractions))
    #     else:
    #         print("Range(B): ", minSize, " - ", maxSize, ": num msgs: ", len(admitFractions))

if __name__ == '__main__':
    sys.exit(main());
