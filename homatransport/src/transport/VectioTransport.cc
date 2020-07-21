//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
//

#include <algorithm>
#include <random>
#include <cmath>
#include <fstream>
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include "VectioTransport.h"
#include "inet/networklayer/common/L3AddressResolver.h"
#include "inet/networklayer/common/InterfaceEntry.h"
#include "inet/networklayer/common/InterfaceTable.h"
#include "inet/networklayer/ipv4/IPv4InterfaceData.h"

Define_Module(VectioTransport);

std::ofstream logFile;
std::ofstream logFile2;
bool logPacketEvents = true;

VectioTransport::VectioTransport()
    : socket()
    , selfMsg(NULL)
    , localPort(-1)
    , destPort(-1)
    , maxDataBytesInPkt(0)
{
    std::random_device rd;
    std::mt19937_64 merceneRand(rd());
    std::uniform_int_distribution<uint64_t> dist(0, UINTMAX_MAX);
    HomaPkt unschePkt = HomaPkt();
    unschePkt.setPktType(PktType::UNSCHED_DATA);
    maxDataBytesInPkt =
            MAX_ETHERNET_PAYLOAD_BYTES - IP_HEADER_SIZE - UDP_HEADER_SIZE -
            unschePkt.headerSize();
}

VectioTransport::~VectioTransport()
{
    cancelAndDelete(selfMsg);
    for (auto incompMsgIter = incompleteRxMsgsMap.begin();
            incompMsgIter !=  incompleteRxMsgsMap.end(); ++incompMsgIter) {
        std::list<InboundMsg*> &rxMsgList = incompMsgIter->second;
        for (auto inbndIter = rxMsgList.begin(); inbndIter != rxMsgList.end();
                ++inbndIter) {
            InboundMsg* incompleteRxMsg = *inbndIter;
            delete incompleteRxMsg;
        }
    }
    cancelAndDelete(inboundGrantQueueTimer);
    cancelAndDelete(outboundGrantQueueTimer);
    cancelAndDelete(sendQueueTimer);
}

void
VectioTransport::initialize()
{
    // Read parameters from the ned file
    localPort = par("localPort");
    destPort = par("destPort");

    // Initialize and schedule the start timer
    selfMsg = new cMessage("stopTimer");
    selfMsg->setKind(SelfMsgKind::START);
    scheduleAt(simTime(), selfMsg);

    // Initialize the inbound grant queue timer
    inboundGrantQueueTimer = new cMessage("inboundGrantQueueTimer");
    inboundGrantQueueTimer->setKind(SelfMsgKind::INBOUNDQUEUE);

    // Initialize the outbound grant queue timer
    outboundGrantQueueTimer = new cMessage("outboundGrantQueueTimer");
    outboundGrantQueueTimer->setKind(SelfMsgKind::OUTBOUNDQUEUE);

    // Initialize the send queue timer
    sendQueueTimer = new cMessage("sendQueueTimer");
    sendQueueTimer->setKind(SelfMsgKind::SENDQUEUE);

    std::string LogFileName = std::string(
                "results/") + std::string(par("logFile").stringValue());
    if (!logFile.is_open()) {
        logFile.open(LogFileName);
    }

    std::string LogFile2Name = std::string(
                "results/tor-test.log");
    if (!logFile2.is_open()) {
        logFile2.open(LogFile2Name);
    }

    logEvents = par("logEvents");

    inboundGrantQueueBusy = false;
    outboundGrantQueueBusy = false;

    assert(sendQueue.empty() == true);
    sendQueueBusy = false;
    sendQueueFreeTime = SIMTIME_ZERO;
    totalSendQueueSizeInBytes = 0;

    srand(1);
}

void
VectioTransport::processStart()
{
    inet::InterfaceTable* ifaceTable =
            check_and_cast<inet::InterfaceTable*>(
            getModuleByPath(par("interfaceTableModule").stringValue()));
    inet::InterfaceEntry* srcIface = NULL;
    inet::IPv4InterfaceData* srcIPv4Data = NULL;
    for (int i=0; i < ifaceTable->getNumInterfaces(); i++) {
        if ((srcIface = ifaceTable->getInterface(i)) &&
                !srcIface->isLoopback() &&
                (srcIPv4Data = srcIface->ipv4Data())) {
            break;
        }
    }
    if (!srcIface) {
        throw cRuntimeError("Can't find a valid interface on the host");
    } else if (!srcIPv4Data) {
        throw cRuntimeError("Can't find an interface with IPv4 address");
    }
    this->srcAddress = inet::L3Address(srcIPv4Data->getIPAddress());
    socket.setOutputGate(gate("udpOut"));
    socket.bind(localPort);
}

void
VectioTransport::processStop()
{}

void
VectioTransport::finish()
{}

void
VectioTransport::handleMessage(cMessage *msg)
{
    if (msg->isSelfMessage()) {
        switch(msg->getKind()) {
            case SelfMsgKind::START:
                processStart();
                break;
            case SelfMsgKind::STOP:
                processStop();
                break;
            case SelfMsgKind::INBOUNDQUEUE:
                processPendingMsgsToSend();
                break;
            case SelfMsgKind::OUTBOUNDQUEUE:
                processPendingMsgsToGrant();
                break;
            case SelfMsgKind::RETXTIMER:
            {
                TimerContext* timerContext = 
                ((TimerContext*) (msg->getContextPointer()));
                processRetxTimer(timerContext);
                break;
            }
            case SelfMsgKind::SENDQUEUE:
                processSendQueue();
                break;
            default:
            {
                throw cRuntimeError("Received SelfMsg of type(%d) is not valid.");
            }
        }
    } else {
        if (msg->arrivedOn("appIn")) {
            processMsgFromApp(check_and_cast<AppMessage*>(msg));
        } else if (msg->arrivedOn("udpIn")) {
            processRcvdPkt(check_and_cast<HomaPkt*>(msg));
        }
    }
}

void
VectioTransport::processMsgFromApp(AppMessage* sendMsg)
{
    // Receive message from the app, store the outbound message state and 
    // send out a request packet
    uint32_t msgByteLen = sendMsg->getByteLength();
    simtime_t msgCreationTime = sendMsg->getMsgCreationTime();
    inet::L3Address destAddr = sendMsg->getDestAddr();
    sendMsg->setSrcAddr(this->srcAddress);
    inet::L3Address srcAddr = sendMsg->getSrcAddr();
    uint32_t firstByte = 0;
    uint32_t lastByte = 0;
    uint32_t bytesToSend = sendMsg->getByteLength();
    uint64_t msgId = ((uint64_t) sendMsg->getMsgId());

    if (logEvents) {
        logFile << simTime() << " Msg: " << msgId 
        << " received from App at src: " << srcAddr 
        << " to: " << destAddr << " size: " 
        << bytesToSend << std::endl;
        logFile.flush();
    }

    // Create an outbound message, and add it to the list of outbound messages
    OutboundMsg* outboundSxMsg = new OutboundMsg();
    outboundSxMsg->msgIdAtSender = msgId;
    outboundSxMsg->numBytesToSend = bytesToSend;
    outboundSxMsg->nextByteToSend = 0; //TODO make sure to define this properly
    outboundSxMsg->msgByteLen = msgByteLen;
    outboundSxMsg->totalBytesOnWire = 0;
    outboundSxMsg->srcAddr = srcAddr;
    outboundSxMsg->destAddr = destAddr;
    outboundSxMsg->msgCreationTime = msgCreationTime;

    this->incompleteSxMsgsMap.insert(
        std::pair<uint64_t,OutboundMsg*>(msgId,outboundSxMsg));

    // Create and forward a request packet for this outbound message
    uint32_t pktDataBytes = 1;
    lastByte = firstByte + pktDataBytes - 1;
    UnschedFields unschedFields;
    unschedFields.msgByteLen = msgByteLen;
    unschedFields.msgCreationTime = msgCreationTime;
    unschedFields.totalUnschedBytes = std::min((int)msgByteLen,freeGrantSize);
    unschedFields.firstByte = firstByte;
    unschedFields.lastByte = lastByte;
    bytesToSend -= pktDataBytes;
    firstByte = lastByte + 1;

    // create and send a req pkt if the freegrantsize is 0
    // otherwise the first unsched data packet will do the job of req pkt
    if (freeGrantSize == 0) {
        HomaPkt* rqPkt = new HomaPkt();
        rqPkt->setSrcAddr(srcAddr);
        rqPkt->setDestAddr(destAddr);
        rqPkt->setMsgId(msgId);
        rqPkt->setPriority(0); 
        rqPkt->setPktType(PktType::REQUEST);
        rqPkt->setUnschedFields(unschedFields);
        rqPkt->setByteLength(pktDataBytes + rqPkt->headerSize());

        // Send the request packet out
        socket.sendTo(rqPkt, rqPkt->getDestAddr(), destPort);
    }

    delete sendMsg;

    // Create free grants and push them to the outboundGrantsQueue
    int bytesToGrant = std::min((int)msgByteLen,freeGrantSize);

    assert(pendingMsgsToSend.find(
        outboundSxMsg->msgIdAtSender) == pendingMsgsToSend.end());
    pendingMsgsToSend.insert(
        std::pair<uint64_t,int>(outboundSxMsg->msgIdAtSender,bytesToGrant));

    if (!inboundGrantQueueBusy){
        processPendingMsgsToSend();
    }
}

void
VectioTransport::processRcvdPkt(HomaPkt* rxPkt)
{
    // Parse the received packet -- whetehr it's REQUEST, GRANT or DATA pkt
    switch (rxPkt->getPktType()) {
        case PktType::REQUEST:
            processReqPkt(rxPkt);
            break;
        case PktType::UNSCHED_DATA:
        case PktType::SCHED_DATA:
            processDataPkt(rxPkt);
            break;
        case PktType::GRANT:
            if (logEvents && rxPkt->getMsgId() == 288){
                logFile << simTime() << " received grant pkt for msg: " 
                << rxPkt->getMsgId() << " at the sender: " 
                << rxPkt->getDestAddr() << " size: " 
                << rxPkt->getGrantFields().grantBytes << std::endl;
                logFile.flush();
            }
            if (pendingMsgsToSend.find(
                rxPkt->getMsgId()) != pendingMsgsToSend.end()){
                pendingMsgsToSend[rxPkt->getMsgId()] += 
                rxPkt->getGrantFields().grantBytes;
                //find the outbound message, update the schedprio
                assert(incompleteSxMsgsMap.find(rxPkt->getMsgId()) !=
                incompleteSxMsgsMap.end());
                incompleteSxMsgsMap[rxPkt->getMsgId()]->schedPrio = 
                rxPkt->getGrantFields().schedPrio;
                assert(rxPkt->getGrantFields().schedPrio >= 2);
                assert(rxPkt->getGrantFields().schedPrio <= 7);
            }
            if (!inboundGrantQueueBusy){
                processPendingMsgsToSend();
            }
            delete rxPkt;
            break;
        case PktType::ACK:
            processAckPkt(rxPkt);
            break;
        case PktType::NACK:
            processNackPkt(rxPkt);
            break;

        default:
            throw cRuntimeError("Received packet type(%d) is not valid.",
                rxPkt->getPktType());
    }
}

void
VectioTransport::processReqPkt(HomaPkt* rxPkt)
{
    if (logEvents) {
        logFile << simTime() << " Received request pkt for msg: " 
        << rxPkt->getMsgId() << " at the receiver: " 
        << rxPkt->getDestAddr() << std::endl;
        logFile.flush();
    }

    // Request pkt for a message received at the receiver 
    // Add the message to the map of flows to be received
    // Send grant packet to the sender for receiving the corresponding flow

    // check if the message already exists in the map
    // if not, add to the map, and create free grants
    uint64_t msgId = rxPkt->getMsgId();
    inet::L3Address srcAddr = rxPkt->getSrcAddr();
    InboundMsg* inboundRxMsg = NULL;
    std::list<InboundMsg*> &rxMsgList = incompleteRxMsgsMap[msgId];
    for (auto inbndIter = rxMsgList.begin(); 
        inbndIter != rxMsgList.end(); ++inbndIter) {
        InboundMsg* incompleteRxMsg = *inbndIter;
        ASSERT(incompleteRxMsg->msgIdAtSender == msgId);
        if (incompleteRxMsg->srcAddr == srcAddr) {
            inboundRxMsg = incompleteRxMsg;
            break;
        }
    }

    // add the message to the map if it doesn't exist
    if (!inboundRxMsg) {
        inboundRxMsg = new InboundMsg(rxPkt, this); 
        rxMsgList.push_front(inboundRxMsg);

        int bytesToSend = inboundRxMsg->msgByteLen;
        int alreadyGrantedBytes = std::min(bytesToSend,freeGrantSize);
        bytesToSend -= alreadyGrantedBytes;
        inboundRxMsg->bytesGranted = alreadyGrantedBytes;
        if (bytesToSend == 0) {
            return;
        }

        if (bytesToSend > 0) {
            // add to pending messages to be granted
            auto itr = pendingMsgsToGrant.find(inboundRxMsg->msgIdAtSender);
            // make sure that the current msg doesn't already exist
            if (itr != pendingMsgsToGrant.end()){
                for (auto itr2 = itr->second.begin(); itr2 != itr->second.end();
                itr2++){
                    auto src = itr2->first;
                    assert(src != inboundRxMsg->srcAddr);
                }
            }
            // add a new pair to the pendingMsgs
            if (itr == pendingMsgsToGrant.end()) {
                std::set<std::pair<inet::L3Address,int>> tempSet;
                tempSet.clear();
                tempSet.insert(std::pair<inet::L3Address,int>(
                    inboundRxMsg->srcAddr,bytesToSend));
                pendingMsgsToGrant.insert(std::pair<uint64_t, 
                std::set<std::pair<inet::L3Address,int>>>(
                    inboundRxMsg->msgIdAtSender,tempSet));
            }
            else {
                itr->second.insert(std::pair<inet::L3Address,int>(
                    inboundRxMsg->srcAddr,bytesToSend));
            }

            if (!outboundGrantQueueBusy) {
                processPendingMsgsToGrant();
            }
        }

        // create a new timercontext to check the missed packets
        TimerContext* timerContext = new TimerContext();
        timerContext->msgIdAtSender = rxPkt->getMsgId();
        timerContext->srcAddr = rxPkt->getSrcAddr();
        timerContext->destAddr = rxPkt->getDestAddr();

        cMessage* retxTimer = new cMessage();
        retxTimer->setKind(SelfMsgKind::RETXTIMER);
        retxTimer->setContextPointer(timerContext);
        scheduleAt(simTime() + inboundRxMsg->retxTimeout,retxTimer);

    }
    else {
        // shouldn't reach here since req packet is only sent if freegrantsize=0
        assert(false);
        return;
    }
    delete rxPkt;
}

void
VectioTransport::processDataPkt(HomaPkt* rxPkt)
{
    if (logEvents && rxPkt->getMsgId() == 288) {
        logFile << simTime() << " Received data pkt for msg: " 
        << rxPkt->getMsgId() << " at the receiver: " << rxPkt->getDestAddr() 
        << " size: " << rxPkt->getDataBytes() << " scheduled at: " 
        << std::endl;
        logFile.flush();
    }

    //update the rtt
    if (rxPkt->getSrcAddr().toIPv4().getDByte(2) != 
        rxPkt->getDestAddr().toIPv4().getDByte(2)) {
    }
    //////////// TESTING PKT DROPS /////////////////
    // int dropPkt = rand() % 20;
    // if (dropPkt == 0){
    //     logFile << "Sorry, dropping this pkt!!!" 
    //     << " Msg: " << rxPkt->getMsgId() << std::endl;
    //     delete rxPkt;
    //     return;
    // }

    ////////////////////////////////////////////////
    // Find the InboundMsg corresponding to this rxPkt in the
    // incompleteRxMsgsMap.
    uint64_t msgId = rxPkt->getMsgId();
    inet::L3Address srcAddr = rxPkt->getSrcAddr();
    InboundMsg* inboundRxMsg = NULL;
    std::list<InboundMsg*> &rxMsgList = incompleteRxMsgsMap[msgId];
    for (auto inbndIter = rxMsgList.begin(); inbndIter != rxMsgList.end();
            ++inbndIter) {
        InboundMsg* incompleteRxMsg = *inbndIter;
        ASSERT(incompleteRxMsg->msgIdAtSender == msgId);
        if (incompleteRxMsg->srcAddr == srcAddr) {
            inboundRxMsg = incompleteRxMsg;
            break;
        }
    }

    if (!inboundRxMsg) {
        //if msg already finished, this probably a duplicate packet, 
        // nothing to do, discard the pkt
        auto itr = finishedMsgs.find(rxPkt->getMsgId());
        if (itr != finishedMsgs.end()) {
            auto itr2 = itr->second.find(rxPkt->getSrcAddr());
            if (itr2 != itr->second.end()) {
                delete rxPkt;
                return;
            }
        }

        //this happens for the first unscheduled packet of any message
        assert(rxPkt->getPktType() == PktType::UNSCHED_DATA);
        inboundRxMsg = new InboundMsg(rxPkt, this); 
        rxMsgList.push_front(inboundRxMsg);

        int bytesToSend = inboundRxMsg->msgByteLen;
        int alreadyGrantedBytes = rxPkt->getUnschedFields().totalUnschedBytes;
        assert(alreadyGrantedBytes <= bytesToSend);
        bytesToSend -= alreadyGrantedBytes;
        inboundRxMsg->bytesGranted = alreadyGrantedBytes;

        inboundRxMsg->firstPktSchedTime = rxPkt->pktScheduleTime;

        // update the inflight granted bytes
        currentRcvInFlightGrantBytes += alreadyGrantedBytes;
        
        // update the inflight granted bytes for the corresponding sender
        cModule* parentHost = this->getParentModule();
        if (senderInFlightGrantBytes.find(rxPkt->getSrcAddr()) != 
        senderInFlightGrantBytes.end()){
            auto itr = senderInFlightGrantBytes.find(rxPkt->getSrcAddr());
            itr->second += alreadyGrantedBytes;
            if (logEvents && strcmp(parentHost->getName(),"nic") == 0
             && parentHost->getIndex() == 0){
                logFile << simTime() <<  " Updating senderinflightgrantbytes: "
                 << " src: " << rxPkt->getSrcAddr() << " (add):" << " bytes: "
                  << itr->second << " pktbytes: " << alreadyGrantedBytes << " msg: "
                   << rxPkt->getMsgId() << std::endl;
            }
        }
        else{
            senderInFlightGrantBytes.insert(std::pair<inet::L3Address,int>(
                rxPkt->getSrcAddr(),alreadyGrantedBytes
            ));
        }

        //add to pending messages to be granted
        if (bytesToSend > 0) {
            auto it = pendingMsgsToGrant.find(inboundRxMsg->msgIdAtSender);
            //make sure that the current Msg doesn't already exist
            if (it != pendingMsgsToGrant.end()) {
                for (auto it2 = it->second.begin(); it2 != it->second.end();
                it2++){
                    auto src = it2->first;
                    assert(src != inboundRxMsg->srcAddr);
                }
            }
            //add a new pair to the pendingMsgs
            if (it == pendingMsgsToGrant.end()) {
                std::set<std::pair<inet::L3Address,int>> tempSet;
                tempSet.clear();
                tempSet.insert(std::pair<inet::L3Address,int>(
                    inboundRxMsg->srcAddr,bytesToSend));
                pendingMsgsToGrant.insert(std::pair<uint64_t, 
                std::set<std::pair<inet::L3Address,int>>>(
                    inboundRxMsg->msgIdAtSender,tempSet));
            }
            else {
                it->second.insert(std::pair<inet::L3Address,int>(
                    inboundRxMsg->srcAddr,bytesToSend));
            }

            if (!outboundGrantQueueBusy) {
                processPendingMsgsToGrant();
            }
        }

        //create a new timercontext to check the missed packets
        TimerContext* timerContext = new TimerContext();
        timerContext->msgIdAtSender = rxPkt->getMsgId();
        timerContext->srcAddr = rxPkt->getSrcAddr();
        timerContext->destAddr = rxPkt->getDestAddr();

        cMessage* retxTimer = new cMessage();
        retxTimer->setKind(SelfMsgKind::RETXTIMER);
        retxTimer->setContextPointer(timerContext);
        scheduleAt(simTime() + inboundRxMsg->retxTimeout,retxTimer);

    }

    // Append the data to the inboundRxMsg and if the msg is complete, remove it
    // from the list of outstanding messages in the map, and send the complete
    // message to the application.
    assert(inboundRxMsg->transport != NULL);
    if (inboundRxMsg->appendPktData(rxPkt)) {
        rxMsgList.remove(inboundRxMsg);
        if (rxMsgList.empty()) {
            incompleteRxMsgsMap.erase(msgId);
        }

        // add the msg information to map of finished msgs
        auto itr = finishedMsgs.find(rxPkt->getMsgId());
        if (itr != finishedMsgs.end()) {
            auto itr2 = itr->second.find(rxPkt->getSrcAddr());
            assert(itr2 == itr->second.end());
            itr->second.insert(rxPkt->getSrcAddr());
        }
        else {
            std::set<inet::L3Address> newSet;
            newSet.clear();
            newSet.insert(rxPkt->getSrcAddr()); 
            finishedMsgs.insert(
                std::pair<uint64_t,
                std::set<inet::L3Address>>(rxPkt->getMsgId(),newSet));
        }

        AppMessage* rxMsg = new AppMessage();
        rxMsg->setDestAddr(inboundRxMsg->destAddr);
        rxMsg->setSrcAddr(inboundRxMsg->srcAddr);
        rxMsg->setMsgCreationTime(inboundRxMsg->msgCreationTime);
        rxMsg->setTransportSchedDelay(SIMTIME_ZERO);
        rxMsg->setByteLength(inboundRxMsg->msgByteLen);
        rxMsg->setMsgBytesOnWire(inboundRxMsg->totalBytesOnWire);
        rxMsg->setFirstPktSchedTime(inboundRxMsg->firstPktSchedTime);
        rxMsg->setMsgId(inboundRxMsg->msgIdAtSender);
        send(rxMsg, "appOut", 0);

        // send an ACK back to sender to delete outboundmsg
        HomaPkt* ackPkt = new HomaPkt();
        ackPkt->setPktType(PktType::ACK);
        ackPkt->setMsgId(msgId);
        ackPkt->setSrcAddr(inboundRxMsg->destAddr);
        ackPkt->setDestAddr(inboundRxMsg->srcAddr);
        ackPkt->setPriority(0);
        socket.sendTo(ackPkt,ackPkt->getDestAddr(),destPort);

        delete inboundRxMsg;

    }
    delete rxPkt;
}


void
VectioTransport::processAckPkt(HomaPkt* rxPkt)
{
    // find the corresponding outbound msg and remove from the map
    auto it = incompleteSxMsgsMap.find(rxPkt->getMsgId());
    assert(it != incompleteSxMsgsMap.end());
    incompleteSxMsgsMap.erase(it);
    if (logEvents) {
    logFile << "Erased flow for msg: " << rxPkt->getMsgId() << std::endl;
    }
    delete rxPkt;
    return;
}

void
VectioTransport::processNackPkt(HomaPkt* rxPkt)
{   
    if (logEvents) {
    logFile << simTime() << " Received NACK pkt" << " Msg: " 
    << rxPkt->getMsgId() << std::endl;
    }
    // check whether the outboundsx msg still exists
    auto itr = incompleteSxMsgsMap.find(rxPkt->getMsgId());
    if (itr != incompleteSxMsgsMap.end()) {
        // resend the data packets corresponding to the first and last bytes
        HomaPkt* resendDataPkt = new HomaPkt();
        resendDataPkt->setPktType(PktType::SCHED_DATA);
        // resendDataPkt->setTimestamp(simTime());
        resendDataPkt->pktScheduleTime = simTime();
        int firstByte = rxPkt->getSchedDataFields().firstByte;
        int lastByte = rxPkt->getSchedDataFields().lastByte;
        if (lastByte - firstByte + 1 < grantSizeBytes) {
            assert(lastByte + 1 == itr->second->msgByteLen);
        }
        else if (lastByte - firstByte + 1 > grantSizeBytes) {
            assert(false);
        }
        resendDataPkt->setMsgId(rxPkt->getMsgId());
        resendDataPkt->setSrcAddr(itr->second->srcAddr);
        resendDataPkt->setDestAddr(itr->second->destAddr);
        SchedDataFields schedFields;
        schedFields.firstByte = firstByte;
        schedFields.lastByte = lastByte;
        resendDataPkt->setSchedDataFields(schedFields);
        resendDataPkt->setPriority(2);
        socket.sendTo(resendDataPkt, resendDataPkt->getDestAddr(),destPort);
        if (logEvents) {
        logFile << simTime() << " Resent pkt: " << firstByte 
        << " " << lastByte << std::endl;
        }
    }
    delete rxPkt;
    return;
}

void
VectioTransport::processPendingMsgsToSend(){
    if (sendQueueBusy == false){
        if (pendingMsgsToSend.empty() != true) {
            inboundGrantQueueBusy = true;
            HomaPkt* dataPkt = extractDataPkt("SRPT");
            dataPkt->pktScheduleTime = simTime();
            int pktByteLen = 0;
            if (dataPkt->getPktType() == PktType::SCHED_DATA || 
            dataPkt->getPktType() == PktType::UNSCHED_DATA){
                if (dataPkt->getPktType() == PktType::SCHED_DATA) {
                    pktByteLen = dataPkt->getSchedDataFields().lastByte - 
                    dataPkt->getSchedDataFields().firstByte + 1;
                    if (logEvents && dataPkt->getMsgId() == 288){
                        logFile << simTime() << " sent sched data pkt for msg: " 
                        << dataPkt->getMsgId() << std::endl;
                    }
                }
                else if (dataPkt->getPktType() == PktType::UNSCHED_DATA) {
                    pktByteLen = dataPkt->getUnschedFields().lastByte - 
                    dataPkt->getUnschedFields().firstByte + 1;
                    if (logEvents && dataPkt->getMsgId() == 288){
                        logFile << simTime() << " sent unsched data pkt for msg: " 
                        << dataPkt->getMsgId() << std::endl;
                    }
                }
                else {
                    assert(false);
                }
                sendQueue.push(dataPkt);
                assert(sendQueueFreeTime <= simTime());
                sendQueueFreeTime = simTime() + ((pktByteLen + 100) * 8.0 / nicBandwidth);
                assert(totalSendQueueSizeInBytes == 0);
                totalSendQueueSizeInBytes += pktByteLen;
            }
            else {
                inboundGrantQueueBusy = false;
                return;
            }

            // schedule the next grant queue processing event after transmission time
            // of data packet corresponding to the current grant packet
            double trans_delay = (pktByteLen + 100) * 8.0 /nicBandwidth; 
            scheduleAt(simTime() + trans_delay + INFINITISIMALTIME, inboundGrantQueueTimer);
            processSendQueue();
            return;
        }
        else {
            inboundGrantQueueBusy = false;
            return;
        }
    }
    else{
        if (pendingMsgsToSend.empty() != true){
            inboundGrantQueueBusy = true;
        }
        assert(sendQueueFreeTime.dbl() >= simTime().dbl());
        scheduleAt(sendQueueFreeTime + INFINITISIMALTIME, inboundGrantQueueTimer);
    }
}

HomaPkt*
VectioTransport::extractDataPkt(const char* schedulingPolicy){
    if (pendingMsgsToSend.size() == 0){
        //send a null data pkt here
        HomaPkt* nonePkt = new HomaPkt();
        nonePkt->setPktType(PktType::NONE);
        return nonePkt;
    }
    // first check the pendingMsgsToSend
    // find the corresponding msg
    // then check the incompletesxmsgs list
    // if the msg does exist there, fine, else, remove the msg from pendinglsgtose
    // update the bytestosend, if they become zero, update the pendingmsgstose

    // then create a data pkt
    // if no data pkt possible, create a data pkt but make its type to be null
    if (schedulingPolicy == "SRPT") {
        // find the message with the smallest remaining bytes to send first
        int minBytesToSend = INT_MAX;
        int minMsgBytesRemaining = INT_MAX;
        uint64_t chosenMsgId;
        auto chosenItr = pendingMsgsToSend.begin();
        bool someMsgToSend = false;
        simtime_t minCreationTime;
        for (auto itr = pendingMsgsToSend.begin(); itr != pendingMsgsToSend.end(); 
        itr++) {
            uint64_t messageID = itr->first; 
            int bytesToSend = itr->second;
            if (bytesToSend == 0){
                continue;
            }
            if (incompleteSxMsgsMap.find(messageID) == incompleteSxMsgsMap.end()){
                pendingMsgsToSend.erase(itr);
                continue;
            }
            else{
                uint32_t msgBytesRemaining = 
                incompleteSxMsgsMap[messageID]->msgByteLen 
                - incompleteSxMsgsMap[messageID]->nextByteToSend;
                assert(bytesToSend > 0);
                assert(msgBytesRemaining > 0);
                if (logEvents && messageID == 288){
                    logFile << simTime() << " bts: " << bytesToSend 
                    << " msgbrem: " << msgBytesRemaining << std::endl;
                }
                assert(bytesToSend <= msgBytesRemaining);

                if (msgBytesRemaining < minMsgBytesRemaining){
                    chosenMsgId = messageID;
                    chosenItr = itr;
                    minBytesToSend = bytesToSend;
                    someMsgToSend = true;
                    minCreationTime = 
                    incompleteSxMsgsMap[messageID]->msgCreationTime;
                }
                else if (msgBytesRemaining == minMsgBytesRemaining){
                    if (incompleteSxMsgsMap[messageID]->msgCreationTime.dbl() < 
                    minCreationTime.dbl()){
                        chosenMsgId = messageID;
                        chosenItr = itr;
                        minBytesToSend = bytesToSend;
                        someMsgToSend = true;
                        minCreationTime = 
                        incompleteSxMsgsMap[messageID]->msgCreationTime;
                    }
                }
            }
        }

        if (someMsgToSend == false) {
            // no msg has any available grant to send
            HomaPkt* nonePkt = new HomaPkt();
            nonePkt->setPktType(PktType::NONE);
            return nonePkt;
        }
        else if (incompleteSxMsgsMap.find(chosenMsgId) 
        == incompleteSxMsgsMap.end()) {
            // remove corresponding msg from pendingMsgsToSend
            pendingMsgsToSend.erase(chosenItr);
            return extractDataPkt(schedulingPolicy);
        }
        else {
            OutboundMsg* outboundSxMsg = incompleteSxMsgsMap[chosenMsgId];

            uint32_t msgByteLen = outboundSxMsg->msgByteLen;
            simtime_t msgCreationTime = outboundSxMsg->msgCreationTime;
            inet::L3Address destAddr = outboundSxMsg->destAddr;
            inet::L3Address srcAddr = outboundSxMsg->srcAddr;
            uint32_t firstByte = outboundSxMsg->nextByteToSend;
            uint32_t lastByte = 0;

            int bytesLeftToSend = minBytesToSend;
            assert(bytesLeftToSend == chosenItr->second);
            assert(bytesLeftToSend <= msgByteLen);

            HomaPkt* sxPkt = new HomaPkt();
            sxPkt->setSrcAddr(srcAddr);
            sxPkt->setDestAddr(destAddr);
            sxPkt->setMsgId(chosenMsgId);
            
            uint32_t pktByteLen = std::min((uint32_t)grantSizeBytes,
            (uint32_t)bytesLeftToSend);
            lastByte = firstByte + pktByteLen - 1;
            int outboundMsgRemBytes = outboundSxMsg->msgByteLen - (lastByte + 1);
            assert(outboundMsgRemBytes >= 0);
            if (lastByte <= freeGrantSize) {
                // send unsched packet
                UnschedFields unschedField;
                unschedField.firstByte = firstByte;
                unschedField.lastByte = lastByte;
                unschedField.msgByteLen = msgByteLen;
                unschedField.msgCreationTime = msgCreationTime;
                unschedField.totalUnschedBytes = std::min((int)msgByteLen,
                freeGrantSize);
                sxPkt->setPktType(PktType::UNSCHED_DATA);
                sxPkt->setUnschedFields(unschedField);
                sxPkt->setPriority(1);
            }
            else {
                // send sched packet
                SchedDataFields schedField;
                schedField.firstByte = firstByte;
                schedField.lastByte = lastByte;
                sxPkt->setPktType(PktType::SCHED_DATA);
                sxPkt->setSchedDataFields(schedField);
                sxPkt->setPriority(outboundSxMsg->schedPrio);
                assert(outboundSxMsg->schedPrio >= 2);
                assert(outboundSxMsg->schedPrio <= 7);
            }
            sxPkt->setByteLength(pktByteLen + sxPkt->headerSize());
            firstByte = lastByte + 1;
            outboundSxMsg->nextByteToSend = firstByte;

            bytesLeftToSend -= pktByteLen;
            assert(bytesLeftToSend >= 0);
            chosenItr->second = bytesLeftToSend;

            return sxPkt;
        }
    }
    else {
        assert(false);
    }
}

void
VectioTransport::processPendingMsgsToGrant(){
    if (pendingMsgsToGrant.empty() != true){
        outboundGrantQueueBusy = true;
        HomaPkt* grntPkt = extractGrantPkt("SRPT");
        if (grntPkt->getPktType() == PktType::NONE){
            // nothing to grant
            delete grntPkt;
            double trans_delay = (freeGrantSize * 8.0 /nicBandwidth);
            scheduleAt(simTime() + trans_delay, outboundGrantQueueTimer);
            return;
        }
        // update the last grant sent to sender time
        auto itrGrantSent = lastGrantSentToSender.find(grntPkt->getDestAddr());
        if(itrGrantSent == lastGrantSentToSender.end()){
            lastGrantSentToSender.insert(std::pair<inet::L3Address,simtime_t>(grntPkt->getDestAddr(),simTime()));
        }
        else{
            assert(itrGrantSent->second <= simTime());
            itrGrantSent->second = simTime();
        }
        auto itrGrantedMsgs = grantedMsgsPerSender.find(grntPkt->getDestAddr());
        if(itrGrantedMsgs == grantedMsgsPerSender.end()){
            std::set<uint64_t> tempSet;
            tempSet.clear();
            tempSet.insert(grntPkt->getMsgId());
            grantedMsgsPerSender.insert(std::pair<inet::L3Address,std::set<uint64_t>>(grntPkt->getDestAddr(), tempSet));
        }
        else{
            itrGrantedMsgs->second.insert(grntPkt->getMsgId());
        }
        if (grntPkt->getMsgId() == 288){
            logFile << simTime() << " sent grant pkt for msg: " 
            << grntPkt->getMsgId() << std::endl;
        }
        assert(grntPkt->getPktType() == PktType::GRANT);
        // socket.sendTo(grntPkt, grntPkt->getDestAddr(), destPort);
        if (sendQueueBusy == false){
            assert(totalSendQueueSizeInBytes == 0);
        }
        // grant pkts can be pushed into the sendqueue even if it is non empty
        // since they are higher priority than data pkts
        sendQueue.push(grntPkt);
        totalSendQueueSizeInBytes += (grntPkt->getByteLength());
        if (sendQueueBusy == false){
            sendQueueFreeTime = simTime() + ((grntPkt->getByteLength() + 100) * 8.0 
            / nicBandwidth);
        }
        else{
            sendQueueFreeTime = sendQueueFreeTime + ((grntPkt->getByteLength() + 100)
             * 8.0 / nicBandwidth);
        }
        // update the bytes granted for the inbound msg
        uint64_t msgId = grntPkt->getMsgId();
        inet::L3Address srcAddr = grntPkt->getDestAddr();
        InboundMsg* inboundRxMsg = NULL;
        std::list<InboundMsg*> &rxMsgList = incompleteRxMsgsMap[msgId];
        for (auto inbndIter = rxMsgList.begin(); 
            inbndIter != rxMsgList.end(); ++inbndIter) {
            InboundMsg* incompleteRxMsg = *inbndIter;
            ASSERT(incompleteRxMsg->msgIdAtSender == msgId);
            if (incompleteRxMsg->srcAddr == srcAddr) {
                inboundRxMsg = incompleteRxMsg;
                break;
            }
        }
        assert(inboundRxMsg != NULL);
        inboundRxMsg->bytesGranted += grntPkt->getGrantFields().grantBytes;

        // schedule the next grant queue processing event after transmission time
        // of data packet corresponding to the current grant packet
        double trans_delay = (grntPkt->getGrantFields().grantBytes + 100) * 8.0 
        /nicBandwidth;
        scheduleAt(simTime() + trans_delay, outboundGrantQueueTimer);

        if (sendQueueBusy == false){
            processSendQueue();
        }
    }
    else{
        outboundGrantQueueBusy = false;
        return;
    }
    
}

HomaPkt*
VectioTransport::extractGrantPkt(const char* schedulingPolicy){
    cModule* parentHost = this->getParentModule();
    if (schedulingPolicy == "SRPT") {
        if (currentRcvInFlightGrantBytes > (int) (degOverComm * 
        allowedInFlightGrantedBytes)){
            //receiver already exceeded the allowed inflight byte limit
            HomaPkt* nonePkt = new HomaPkt();
            nonePkt->setPktType(PktType::NONE);
            return nonePkt;
        }

        // find the msg with smallest remaining bytes to grant first
        
        std::set<inet::L3Address> sendersToExclude;
        sendersToExclude.clear();

        uint64_t chosenMsgId;
        inet::L3Address chosenSrcAddr;
        assert(pendingMsgsToGrant.size() > 0);
        auto chosenItr = pendingMsgsToGrant.begin();
        auto chosenItr2 = chosenItr->second.begin();
        uint16_t assignedPrio = 2;

        do{
            int minBytesToGrant = INT_MAX;
            simtime_t minCreationTime;
            // uint64_t chosenMsgId;
            // inet::L3Address chosenSrcAddr;
            // assert(pendingMsgsToGrant.size() > 0);
            chosenItr = pendingMsgsToGrant.begin();
            chosenItr2 = chosenItr->second.begin();
            bool someMsgChosen = false;
            // find the top non excluded msg
            if (logEvents && strcmp(parentHost->getName(),"nic") == 0 
            && parentHost->getIndex() == 0){
                logFile << simTime() << " Looping over pending msgs to grant: " 
                << " (senders to exclude: ";
                if (sendersToExclude.empty()){
                    logFile << "none";
                }
                for (auto steItr = sendersToExclude.begin(); steItr != 
                sendersToExclude.end(); steItr++){
                    logFile << *steItr << " ";
                }
                logFile << std::endl;
            }
            for (auto itr = pendingMsgsToGrant.begin(); itr != 
            pendingMsgsToGrant.end();itr++){
                uint64_t messageID = itr->first;
                for (auto itr2 = itr->second.begin(); itr2 != itr->second.end();
                itr2++){
                    inet::L3Address messageSrcAddr = itr2->first;
                    int bytesToGrant = itr2->second;
                    assert(bytesToGrant > 0);
                    // find the creation time of this message as well

                    InboundMsg* inboundRxMsg = NULL;
                    std::list<InboundMsg*> &rxMsgList = 
                    incompleteRxMsgsMap[messageID];
                    for (auto inbndIter = rxMsgList.begin(); 
                        inbndIter != rxMsgList.end(); ++inbndIter) {
                        InboundMsg* incompleteRxMsg = *inbndIter;
                        ASSERT(incompleteRxMsg->msgIdAtSender == messageID);
                        if (incompleteRxMsg->srcAddr == messageSrcAddr) {
                            inboundRxMsg = incompleteRxMsg;
                            break;
                        }
                    }
                    assert(inboundRxMsg != NULL);
                    if (logEvents && strcmp(parentHost->getName(),"nic") == 0 && 
                    parentHost->getIndex() == 0){
                        logFile << " id:" << messageID << " src:" << messageSrcAddr
                         << " btg:" << bytesToGrant 
                        << " ct:" << inboundRxMsg->msgCreationTime << " ::::: ";
                    }


                    if (bytesToGrant < minBytesToGrant && 
                    sendersToExclude.find(messageSrcAddr) == 
                    sendersToExclude.end()){
                        chosenMsgId = messageID;
                        chosenSrcAddr = messageSrcAddr;
                        chosenItr = itr;
                        chosenItr2 = itr2;
                        minBytesToGrant = bytesToGrant;
                        someMsgChosen = true;
                        minCreationTime = inboundRxMsg->msgCreationTime;
                    }
                    else if (bytesToGrant == minBytesToGrant && 
                    sendersToExclude.find(messageSrcAddr) == 
                    sendersToExclude.end()){
                        if (inboundRxMsg->msgCreationTime < minCreationTime){
                            chosenMsgId = messageID;
                            chosenSrcAddr = messageSrcAddr;
                            chosenItr = itr;
                            chosenItr2 = itr2;
                            minBytesToGrant = bytesToGrant;
                            someMsgChosen = true;
                            minCreationTime = inboundRxMsg->msgCreationTime;
                        }
                    }
                }
            }

            if (logEvents && strcmp(parentHost->getName(),"nic") == 0 
            && parentHost->getIndex() == 0){
                logFile << " something chosen: " << someMsgChosen << std::endl;
            }

            if (someMsgChosen == false){
                // no msg could be chosen because of 
                // the in flight byte constraints
                HomaPkt* nonePkt = new HomaPkt();
                nonePkt->setPktType(PktType::NONE);
                return nonePkt;
            }
            if (logEvents && strcmp(parentHost->getName(),"nic") == 0
             && parentHost->getIndex() == 0){
                logFile << " temp chosen msg: " << chosenMsgId << " src: " 
                << chosenSrcAddr << " btg: " << minBytesToGrant << " ct: " 
                << minCreationTime << std::endl;
            }
            assert(senderInFlightGrantBytes.find(chosenSrcAddr) !=
            senderInFlightGrantBytes.end());
            auto senderBytesItr = senderInFlightGrantBytes.find(chosenSrcAddr);
            
            // if not heard from the chosen sender until the threshold time
            // reset the senderInFlightBytes counter and the total bytes in flight counter
            auto itrLastHeard = this->lastHeardFromSender.find(chosenSrcAddr);
            auto itrLastGrant = this->lastGrantSentToSender.find(chosenSrcAddr);
            if(itrLastHeard != this->lastHeardFromSender.end() &&
            itrLastGrant != this->lastGrantSentToSender.end()){
                simtime_t lastHeardTime = itrLastHeard->second;
                simtime_t lastGrantTime = itrLastGrant->second;
                if((lastGrantTime > lastHeardTime) &&
                (senderBytesItr->second > 0)  && 
                (simTime() - lastGrantTime >= this->lastHeardThreshold) &&
                (simTime() - lastHeardTime >= this->lastHeardThreshold)){
                    auto itrGrantedMsgs = this->grantedMsgsPerSender.find(chosenSrcAddr);
                    assert(itrGrantedMsgs != this->grantedMsgsPerSender.end());
                    if(itrGrantedMsgs->second.find(chosenMsgId) == itrGrantedMsgs->second.end()){
                        this->extraGrantedBytes += senderBytesItr->second;
                        currentRcvInFlightGrantBytes -= senderBytesItr->second;
                        senderBytesItr->second = 0;
                        assert(currentRcvInFlightGrantBytes >= 0);
                        logFile << simTime() << " extra granted bytes for sender: " << chosenSrcAddr << " : " << this->extraGrantedBytes  << " chosen msg: " << chosenMsgId << std::endl;
                        logFile.flush();
                        assert(simTime() - lastHeardTime >= 0);
                        itrLastHeard->second = simTime();
                    }
                }
            }

            if (senderBytesItr->second > allowedInFlightGrantedBytes){
                sendersToExclude.insert(chosenSrcAddr);
                assignedPrio++;
                if (logEvents && strcmp(parentHost->getName(),"nic") == 0 && 
                parentHost->getIndex() == 0){
                    logFile << "Excluding sender: " << chosenSrcAddr 
                    << " sender bytes: " << senderBytesItr->second
                     << " allowed: " << allowedInFlightGrantedBytes << std::endl;
                }
            }
            else{
                auto checkItr = senderActiveGrantedMsg.find(chosenSrcAddr);
                if (checkItr == senderActiveGrantedMsg.end()){
                    senderActiveGrantedMsg.insert(
                        std::pair<inet::L3Address,std::pair<uint64_t,int>>(
                            chosenSrcAddr,std::pair<uint64_t,int>(
                                chosenMsgId,minBytesToGrant
                            )
                        )
                    );
                    break;
                }
                else{
                    if (chosenMsgId == (checkItr->second).first){
                        assert(minBytesToGrant == (checkItr->second).second);
                        break;
                    }
                    else if (minBytesToGrant < (checkItr->second).second){
                        // update the active sender msg
                        checkItr->second = std::pair<uint64_t,int>(
                            chosenMsgId,minBytesToGrant);
                        break;
                    }
                    else{
                        // try choosing another sender
                        sendersToExclude.insert(chosenSrcAddr);
                        assignedPrio++;
                        if (logEvents && strcmp(parentHost->getName(),"nic") == 0
                         && parentHost->getIndex() == 0){
                            logFile << "Excluding sender: " << chosenSrcAddr 
                            << " wanted to grant: " << minBytesToGrant
                             << " actively granting: " << (checkItr->second).second 
                             << " for msg: " << (checkItr->second).first << std::endl;
                        }
                    }
                }
            }
        }while(1);

        if (logEvents && strcmp(parentHost->getName(),"nic") == 0 
        && parentHost->getIndex() == 0){
            logFile << simTime() << " Finally chosen msg: " << chosenMsgId 
            << " src: " << chosenSrcAddr << std::endl;
        }
        // create grant packet using the chosen message
        assert(chosenItr == pendingMsgsToGrant.find(chosenMsgId));
        
        uint32_t pktDataBytes = std::min(chosenItr2->second, 
        this->grantSizeBytes);
        HomaPkt* grntPkt = new HomaPkt();
        GrantFields grantFields;
        grantFields.grantBytes = pktDataBytes;
        grantFields.isFree = false;
        if (assignedPrio > 7){
            //assuming 8 priority levels
            //TODO take input the desired number of priority levels
            assignedPrio = 7;
        }
        grantFields.schedPrio = assignedPrio;
        grntPkt->setSrcAddr(srcAddress);
        grntPkt->setDestAddr(chosenSrcAddr);
        grntPkt->setMsgId(chosenMsgId);
        grntPkt->setPriority(0);
        grntPkt->setPktType(PktType::GRANT);
        grntPkt->setGrantFields(grantFields);
        grntPkt->setByteLength(grntPkt->headerSize());
        auto remainingBytesToGrant = chosenItr2->second - pktDataBytes;

        currentRcvInFlightGrantBytes += pktDataBytes;

        assert(senderInFlightGrantBytes.find(chosenSrcAddr) != 
        senderInFlightGrantBytes.end());
        auto senderItr = senderInFlightGrantBytes.find(chosenSrcAddr);
        senderItr->second += pktDataBytes;
        if (logEvents && strcmp(parentHost->getName(),"nic") == 0
         && parentHost->getIndex() == 0){
            logFile << simTime() <<  " Updating senderinflightgrantbytes: "
             << " src: " << chosenSrcAddr << " (add2):" << " bytes: " 
             << senderItr->second << " pktbytes: " << pktDataBytes << " msg: " 
             << chosenMsgId << std::endl;
        }

        chosenItr->second.erase(chosenItr2);

        assert(senderActiveGrantedMsg.find(chosenSrcAddr) !=
        senderActiveGrantedMsg.end());
        auto senderActiveMsgItr = senderActiveGrantedMsg.find(chosenSrcAddr);
        senderActiveMsgItr->second.second -= pktDataBytes;
        assert(senderActiveMsgItr->second.second >= 0);
        if (senderActiveMsgItr->second.second == 0){
            senderActiveGrantedMsg.erase(senderActiveMsgItr);
        }

        if (remainingBytesToGrant > 0) {
            chosenItr->second.insert(std::pair<inet::L3Address,int>(
                chosenSrcAddr,remainingBytesToGrant));
        }
        else if (remainingBytesToGrant == 0) {
            if (chosenItr->second.size() == 0) {
                pendingMsgsToGrant.erase(chosenItr);
            }
        }
        else {
            assert(false);
        }
        return grntPkt;

    }
    else {
        assert(false);    
    }
}

void
VectioTransport::processSendQueue(){
    if (sendQueue.empty() == true){
        sendQueueBusy = false;
        return;
    }
    else{
        sendQueueBusy = true;
        HomaPkt* sxPkt = sendQueue.front();
        sendQueue.pop();
        int pktBytes = 0;
        if (sxPkt->getPktType() == PktType::UNSCHED_DATA){
            pktBytes = sxPkt->getUnschedFields().lastByte - sxPkt->getUnschedFields().firstByte + 1;
        }
        else if (sxPkt->getPktType() == PktType::SCHED_DATA){
            pktBytes = sxPkt->getSchedDataFields().lastByte - sxPkt->getSchedDataFields().firstByte + 1;
        }
        else if (sxPkt->getPktType() == PktType::GRANT){
            pktBytes = sxPkt->getByteLength();
            // logFile << " length for grant pkt = " << pktBytes << std::endl;
        }
        totalSendQueueSizeInBytes -= (pktBytes);
        assert(totalSendQueueSizeInBytes >= 0);
        socket.sendTo(sxPkt,sxPkt->getDestAddr(),localPort);
        double trans_delay = (pktBytes + 100) * 8.0 /nicBandwidth;
        scheduleAt(simTime() + trans_delay, sendQueueTimer);
        return;
    }
}

void
VectioTransport::processRetxTimer(TimerContext* timerContext)
{
    // checks if the corresponding inboundmsg still exists
    // if it does, checks if the missing pkt is still missing
    // if it is, sends a NACK

    uint64_t msgId = timerContext->msgIdAtSender;
    inet::L3Address srcAddr = timerContext->srcAddr;
    InboundMsg* inboundRxMsg = NULL;
    std::list<InboundMsg*> &rxMsgList = incompleteRxMsgsMap[msgId];
    for (auto inbndIter = rxMsgList.begin(); 
        inbndIter != rxMsgList.end(); ++inbndIter){
        InboundMsg* incompleteRxMsg = *inbndIter;
        ASSERT(incompleteRxMsg->msgIdAtSender == msgId);
        if (incompleteRxMsg->srcAddr == srcAddr) {
            inboundRxMsg = incompleteRxMsg;
            break;
        }
    }

    if (inboundRxMsg != NULL) {
        inboundRxMsg->checkAndSendNack();
    }
    else {
        // make sure the msg is finished otherwise
        auto itr = finishedMsgs.find(msgId);
        assert(itr != finishedMsgs.end());
        auto itr2 = itr->second.find(srcAddr);
        assert(itr2 != itr->second.end());
    }

    return;

}

VectioTransport::InboundMsg::InboundMsg()
    : numBytesToRecv(0)
    , msgByteLen(0)
    , totalBytesOnWire(0)
    , srcAddr()
    , destAddr()
    , msgIdAtSender(0)
    , msgCreationTime(SIMTIME_ZERO)
{}

VectioTransport::InboundMsg::InboundMsg(HomaPkt* rxPkt, VectioTransport* transport)
    : numBytesToRecv(0)
    , msgByteLen(0)
    , totalBytesOnWire(0)
    , srcAddr(rxPkt->getSrcAddr())
    , destAddr(rxPkt->getDestAddr())
    , msgIdAtSender(rxPkt->getMsgId())
    , msgCreationTime(SIMTIME_ZERO)
    , transport(transport)
{
    numBytesToRecv = rxPkt->getUnschedFields().msgByteLen;
    msgByteLen = numBytesToRecv;
    msgCreationTime = rxPkt->getUnschedFields().msgCreationTime;
    // transport = transport;
    assert(transport != NULL);
}

VectioTransport::InboundMsg::~InboundMsg()
{}

void
VectioTransport::InboundMsg::checkAndSendNack()
{
    // at the timeout event, checks whether the missed pkt still exists
    // if yes, send a NACK to the sender
    if (numBytesToRecv == 0) {
        return;
        //assert the message is finished
    }
    else if (bytesGranted < msgByteLen) {
        TimerContext* timerContext = new TimerContext();
        timerContext->msgIdAtSender = msgIdAtSender;
        timerContext->srcAddr = srcAddr;
        timerContext->destAddr = destAddr;

        cMessage* retxTimer = new cMessage();
        retxTimer->setKind(SelfMsgKind::RETXTIMER);
        retxTimer->setContextPointer(timerContext);
        transport->scheduleAt(simTime() + retxTimeout,retxTimer);
        return;
    }
    else{
        if (missedPkts.size() > 0) {
            // send a NACK for every missed packet
            for (auto itr=missedPkts.begin(); itr != missedPkts.end(); itr++) {
                int missedPktSeqNo = itr->first;
                HomaPkt* nackPkt = new HomaPkt();
                nackPkt->setPktType(PktType::NACK);
                nackPkt->setSrcAddr(destAddr);
                nackPkt->setDestAddr(srcAddr);
                nackPkt->setMsgId(msgIdAtSender);
                nackPkt->setPriority(0);
                SchedDataFields schedFields;
                uint32_t firstByte = missedPktSeqNo * transport->grantSizeBytes;
                uint32_t lastByte = firstByte + transport->grantSizeBytes - 1;
                if (lastByte + 1 > msgByteLen){
                    lastByte = msgByteLen - 1;
                }
                schedFields.firstByte = firstByte;
                schedFields.lastByte = lastByte;
                nackPkt->setSchedDataFields(schedFields);
                transport->socket.sendTo(nackPkt,nackPkt->getDestAddr(),
                transport->destPort);
                if (transport->logEvents) {
                logFile << "Sent nack for missed pkt: " << firstByte 
                << " " << lastByte << " Msg: " << msgIdAtSender << std::endl;
                }
            }
        }
        if (largestByteRcvd < bytesGranted - 1) {
            // send a NACK for every last unrcvd packet
            for (int newFirstByte=largestByteRcvd+1; 
            newFirstByte <= bytesGranted-1; 
            newFirstByte = newFirstByte + transport->grantSizeBytes){
                HomaPkt* nackPkt = new HomaPkt();
                nackPkt->setPktType(PktType::NACK);
                nackPkt->setSrcAddr(destAddr);
                nackPkt->setDestAddr(srcAddr);
                nackPkt->setMsgId(msgIdAtSender);
                nackPkt->setPriority(0);
                SchedDataFields schedFields;
                uint32_t firstByte = newFirstByte;
                uint32_t lastByte = firstByte + transport->grantSizeBytes - 1;
                if (lastByte + 1 > bytesGranted){
                    lastByte = bytesGranted - 1;
                }
                schedFields.firstByte = firstByte;
                schedFields.lastByte = lastByte;
                nackPkt->setSchedDataFields(schedFields);
                transport->socket.sendTo(nackPkt,nackPkt->getDestAddr(),
                transport->destPort);
                if (transport->logEvents) {
                logFile << "Sent nack for last missed pkt: " << firstByte 
                << " " << lastByte << " Msg: " << msgIdAtSender << std::endl;
                }
            }
        }

        // create timer for checking again
        TimerContext* timerContext = new TimerContext();
        timerContext->msgIdAtSender = msgIdAtSender;
        timerContext->srcAddr = srcAddr;
        timerContext->destAddr = destAddr;

        cMessage* retxTimer = new cMessage();
        retxTimer->setKind(SelfMsgKind::RETXTIMER);
        retxTimer->setContextPointer(timerContext);
        transport->scheduleAt(simTime() + retxTimeout,retxTimer);
        return;
    }
}

bool
VectioTransport::InboundMsg::updateRxAndMissedPkts(int pktSeqNo)
{
    // if pktSeqNo = largest pktsseq no + 1, just update the 
    if (pktSeqNo == largestPktSeqRcvd + 1) {
        //no new misses, nothing to do
        return false;
    }
    else if (pktSeqNo > largestPktSeqRcvd + 1) {
        // some pkts missed, update  missedPkts
        // create timeout event to later check and send NACK
        for (int i=largestPktSeqRcvd+1; i<pktSeqNo;i++){
            auto itr = missedPkts.find(i);
            assert(itr == missedPkts.end());
            missedPkts.insert(std::pair<int,simtime_t>(i,simTime()));
        }
        return false;
    }
    else if (pktSeqNo <= largestPktSeqRcvd) {
        // pkt which was previously missed, update missedPkts
        auto itr = missedPkts.find(pktSeqNo);
        if (itr != missedPkts.end()){
            missedPkts.erase(itr);
            return false;
        }
        else {
            return true;
        }
    }
}

VectioTransport::OutboundMsg::OutboundMsg()
    : msgByteLen(0)
    , totalBytesOnWire(0)
    , srcAddr()
    , destAddr()
    , msgIdAtSender(0)
    , msgCreationTime(SIMTIME_ZERO)
{}

VectioTransport::OutboundMsg::~OutboundMsg()
{}

bool
VectioTransport::InboundMsg::appendPktData(HomaPkt* rxPkt)
{   
    SchedDataFields schedFields;
    UnschedFields unschedFields;
    uint32_t dataBytesInPkt;
    int lastByte;
    int pktSeqNo;
    if (rxPkt->getPktType() == PktType::SCHED_DATA) {
        schedFields = rxPkt->getSchedDataFields();
        dataBytesInPkt =
        schedFields.lastByte - schedFields.firstByte + 1;
        pktSeqNo = schedFields.firstByte / (this->transport)->grantSizeBytes;
        lastByte = schedFields.lastByte;
        if (transport->logEvents) {
            logFile << "pkt seq no: " << pktSeqNo << " first: " 
            << schedFields.firstByte << " last: " << schedFields.lastByte 
            << " data: " << dataBytesInPkt << std::endl;
        }
        logFile.flush();
    }
    else {
        assert(rxPkt->getPktType() == PktType::UNSCHED_DATA);
        unschedFields = rxPkt->getUnschedFields();
        dataBytesInPkt =
        unschedFields.lastByte - unschedFields.firstByte + 1;
        pktSeqNo = unschedFields.firstByte / transport->grantSizeBytes;
        lastByte = unschedFields.lastByte;
        if (transport->logEvents) {
            logFile << "pkt seq no: " << pktSeqNo << " first: " 
            << unschedFields.firstByte << " last: " << unschedFields.lastByte 
            << " data: " << dataBytesInPkt << std::endl;
        }
        logFile.flush();
    }
    ASSERT((rxPkt->getSrcAddr() == srcAddr) &&
            (rxPkt->getDestAddr() == destAddr) &&
            (rxPkt->getMsgId() == msgIdAtSender));

    bool isPktDuplicate = updateRxAndMissedPkts(pktSeqNo);

    // update the largest received pkt seqno
    if (pktSeqNo > largestPktSeqRcvd) {
        largestPktSeqRcvd = pktSeqNo;
        assert(lastByte > largestByteRcvd);
        largestByteRcvd = lastByte;
    }

    if (!isPktDuplicate) {
        numBytesToRecv -= dataBytesInPkt;

        // update the in flight bytes
        assert(transport->senderInFlightGrantBytes.find(rxPkt->getSrcAddr()) !=
        transport->senderInFlightGrantBytes.end());
        auto itr = transport->senderInFlightGrantBytes.find(rxPkt->getSrcAddr());

        if(itr->second >= dataBytesInPkt){
            itr->second -= dataBytesInPkt;
            assert(itr->second >= 0);
            transport->currentRcvInFlightGrantBytes -= dataBytesInPkt;
            assert(transport->currentRcvInFlightGrantBytes >= 0);
        }
        else{
            // remove extra bytes from extra grants
            int extraBytesToRemove = dataBytesInPkt - itr->second;
            transport->currentRcvInFlightGrantBytes -= itr->second;
            assert(transport->currentRcvInFlightGrantBytes >= 0);
            itr->second = 0;
            transport->extraGrantedBytes -= extraBytesToRemove;
            assert(transport->extraGrantedBytes >= 0);
        }

        if(rxPkt->getPktType() == PktType::SCHED_DATA){
            if(transport->lastHeardFromSender.find(rxPkt->getSrcAddr()) == transport->lastHeardFromSender.end() ){
                transport->lastHeardFromSender.insert(std::pair<inet::L3Address,simtime_t>(rxPkt->getSrcAddr(),simTime()));
            }
            else{
                auto itrLastHeard = transport->lastHeardFromSender.find(rxPkt->getSrcAddr());
                assert(itrLastHeard->second <= simTime());
                itrLastHeard->second = simTime();
            }
        }

        cModule* parentHost = this->transport->getParentModule();
        if (transport->logEvents && strcmp(parentHost->getName(),"nic") == 0 
        && parentHost->getIndex() == 0){
            logFile << simTime() <<  " Updating senderinflightgrantbytes: "
             << " src: " << rxPkt->getSrcAddr() << " bytes: " << itr->second 
             << " pktbytes: " << dataBytesInPkt << " msg: " << rxPkt->getMsgId()
              << std::endl;
        }
    }
    if (numBytesToRecv < 0) {
        throw cRuntimeError("Remaining bytes to "
        "receive for an inbound msg can't be negative.");
    }

    if (numBytesToRecv == 0) {
        return true;
    } else {
        return false;
    }
}
