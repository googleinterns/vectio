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
#include "VectioTransport.h"
#include "inet/networklayer/common/L3AddressResolver.h"
#include "inet/networklayer/common/InterfaceEntry.h"
#include "inet/networklayer/common/InterfaceTable.h"
#include "inet/networklayer/ipv4/IPv4InterfaceData.h"

Define_Module(VectioTransport);

std::ofstream logFile;
bool logPacketEvents = false;

VectioTransport::VectioTransport()
    : socket()
    , selfMsg(NULL)
    , localPort(-1)
    , destPort(-1)
    , msgId(0)
    , maxDataBytesInPkt(0)
{
    std::random_device rd;
    std::mt19937_64 merceneRand(rd());
    std::uniform_int_distribution<uint64_t> dist(0, UINTMAX_MAX);
    msgId = dist(merceneRand);
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
    inboundGrantQueueTimer->setKind(SelfMsgKind::IBGRANTQUEUE);

    // Initialize the outbound grant queue timer
    outboundGrantQueueTimer = new cMessage("outboundGrantQueueTimer");
    outboundGrantQueueTimer->setKind(SelfMsgKind::OBGRANTQUEUE);

    std::string LogFileName = std::string(
                "results/") + std::string(par("logFile").stringValue());
    if(!logFile.is_open()) {
        logFile.open(LogFileName);
    }

    logEvents = par("logEvents");

    inboundGrantQueueBusy = false;
    outboundGrantQueueBusy = false;

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
            case SelfMsgKind::IBGRANTQUEUE:
                processPendingMsgsToSend();
                break;
            case SelfMsgKind::OBGRANTQUEUE:
                processPendingMsgsToGrant();
                break;
            case SelfMsgKind::RETXTIMER:
            {
                TimerContext* timerContext = ((TimerContext*) (msg->getContextPointer()));
                processRetxTimer(timerContext);
                break;
            }
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

    if(logEvents){
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

    //create and send a req pkt if the freegrantsize is 0
    //otherwise the first unsched data packet will do the job of req pkt
    if(freeGrantSize == 0){
        HomaPkt* rqPkt = new HomaPkt();
        rqPkt->setSrcAddr(srcAddr);
        rqPkt->setDestAddr(destAddr);
        rqPkt->setMsgId(msgId);
        // rqPkt->setPriority(bytesToSend); //TODO think about priority for rqpkt
        rqPkt->setPktType(PktType::REQUEST);
        rqPkt->setUnschedFields(unschedFields);
        rqPkt->setByteLength(pktDataBytes + rqPkt->headerSize());

        // Send the request packet out
        socket.sendTo(rqPkt, rqPkt->getDestAddr(), destPort);
    }

    delete sendMsg;
    ++msgId;

    // Create free grants and push them to the outboundGrantsQueue
    int bytesToGrant = std::min((int)msgByteLen,freeGrantSize);
    // do{
    //     uint32_t pktDataBytes = std::min(bytesToGrant, this->grantSizeBytes);
    //     HomaPkt* grntPkt = new HomaPkt();
    //     GrantFields grantFields;
    //     grantFields.grantBytes = pktDataBytes;
    //     grantFields.isFree = true;
    //     grntPkt->setSrcAddr(outboundSxMsg->destAddr);
    //     grntPkt->setDestAddr(outboundSxMsg->srcAddr);
    //     grntPkt->setMsgId(outboundSxMsg->msgIdAtSender);
    //     // grntPkt->setPriority(bytesToSend); //TODO think about the priority for grntPkt
    //     grntPkt->setPktType(PktType::GRANT);
    //     grntPkt->setGrantFields(grantFields);
    //     grntPkt->setByteLength(grntPkt->headerSize());
    //     bytesToGrant -= pktDataBytes;
    //     assert(bytesToGrant >= 0);

    //     // Send the packet out
    //     inboundGrantQueue.push(grntPkt);
    // }while(bytesToGrant > 0);

    assert(pendingMsgsToSend.find(outboundSxMsg->msgIdAtSender) == pendingMsgsToSend.end());
    pendingMsgsToSend.insert(std::pair<uint64_t,int>(outboundSxMsg->msgIdAtSender,bytesToGrant));

    if(!inboundGrantQueueBusy){
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
            if(logEvents){
                logFile << simTime() << " received grant pkt for msg: " << 
                rxPkt->getMsgId() << " at the sender: " << rxPkt->getDestAddr() << 
                " size: " << rxPkt->getGrantFields().grantBytes << std::endl;
                logFile.flush();
            }
            // inboundGrantQueue.push(rxPkt);
            if(pendingMsgsToSend.find(rxPkt->getMsgId()) != pendingMsgsToSend.end()){
                pendingMsgsToSend[rxPkt->getMsgId()] += rxPkt->getGrantFields().grantBytes;
            }
            if(!inboundGrantQueueBusy){
                processPendingMsgsToSend();
            }
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
    if(logEvents){
        logFile << simTime() << " Received request pkt for msg: " 
        << rxPkt->getMsgId() << " at the receiver: " 
        << rxPkt->getDestAddr() << std::endl;
        logFile.flush();
    }

    // Request pkt for a message received at the receiver 
    // Add the message to the map of flows to be received
    // Send grant packet to the sender for receiving the corresponding flow

    //check if the message already exists in the map
    //if not, add to the map, and create free grants
    uint64_t msgId = rxPkt->getMsgId();
    inet::L3Address srcAddr = rxPkt->getSrcAddr();
    InboundMsg* inboundRxMsg = NULL;
    std::list<InboundMsg*> &rxMsgList = incompleteRxMsgsMap[msgId];
    for(auto inbndIter = rxMsgList.begin(); 
        inbndIter != rxMsgList.end(); ++inbndIter){
        InboundMsg* incompleteRxMsg = *inbndIter;
        ASSERT(incompleteRxMsg->msgIdAtSender == msgId);
        if (incompleteRxMsg->srcAddr == srcAddr) {
            inboundRxMsg = incompleteRxMsg;
            break;
        }
    }

    //add the message to the map if it doesn't exist
    if(!inboundRxMsg){
        inboundRxMsg = new InboundMsg(rxPkt, this); 
        rxMsgList.push_front(inboundRxMsg);

        int bytesToSend = inboundRxMsg->msgByteLen;
        int alreadyGrantedBytes = std::min(bytesToSend,freeGrantSize);
        bytesToSend -= alreadyGrantedBytes;
        inboundRxMsg->bytesGranted = alreadyGrantedBytes;
        if(bytesToSend == 0){
            return;
        }
        //create and send per-packet grants for the message
        // do{
        //     uint32_t pktDataBytes = std::min(bytesToSend, this->grantSizeBytes);
        //     HomaPkt* grntPkt = new HomaPkt();
        //     GrantFields grantFields;
        //     grantFields.grantBytes = pktDataBytes;
        //     grantFields.isFree = false;
        //     grntPkt->setSrcAddr(inboundRxMsg->destAddr);
        //     grntPkt->setDestAddr(inboundRxMsg->srcAddr);
        //     grntPkt->setMsgId(inboundRxMsg->msgIdAtSender);
        //     // grntPkt->setPriority(bytesToSend); //TODO think about the priority for grntPkt
        //     grntPkt->setPktType(PktType::GRANT);
        //     grntPkt->setGrantFields(grantFields);
        //     grntPkt->setByteLength(grntPkt->headerSize());
        //     bytesToSend -= pktDataBytes;
        //     assert(bytesToSend >= 0);

        //     // Send the packet out
        //     // outboundGrantQueue.push(grntPkt);
        // }while(bytesToSend > 0);

        if(bytesToSend > 0){
            //add to pending messages to be granted
            auto itr = pendingMsgsToGrant.find(inboundRxMsg->msgIdAtSender);
            //make sure that the current Msg doesn't already exist
            if(itr != pendingMsgsToGrant.end()){
                for(auto itr2 = itr->second.begin(); itr2 != itr->second.end();
                itr2++){
                    auto src = itr2->first;
                    assert(src != inboundRxMsg->srcAddr);
                }
            }
            //add a new pair to the pendingMsgs
            if(itr == pendingMsgsToGrant.end()){
                std::set<std::pair<inet::L3Address,int>> tempSet;
                tempSet.clear();
                tempSet.insert(std::pair<inet::L3Address,int>(
                    inboundRxMsg->srcAddr,bytesToSend));
                pendingMsgsToGrant.insert(std::pair<uint64_t, 
                std::set<std::pair<inet::L3Address,int>>>(
                    inboundRxMsg->msgIdAtSender,tempSet));
            }
            else{
                itr->second.insert(std::pair<inet::L3Address,int>(inboundRxMsg->srcAddr,bytesToSend));
            }

            if(!outboundGrantQueueBusy){
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
    else{
        //shouldn't reach here since req packet is only sent if freegrantsize=0
        assert(false);
        //nothing to be done, if the msg already exists in the map
        return;
    }
}

void
VectioTransport::processGrantPkt(HomaPkt* rxPkt)
{
    if(logEvents){
        logFile << simTime() << " Received grant pkt for msg: " 
        << rxPkt->getMsgId() << " at the sender: " << rxPkt->getDestAddr() 
        << " size: " << rxPkt->getGrantFields().grantBytes << std::endl;
        logFile.flush();
    }
    // Grant pkt for a message received at the sender
    // Send the data packets corresponding to the message
    // Remove the message from the map once done sending all the packets
    uint64_t msgId = rxPkt->getMsgId();

    //make sure the msg exists in the map
    if(incompleteSxMsgsMap.find(msgId) != incompleteSxMsgsMap.end()){
        OutboundMsg* outboundSxMsg = incompleteSxMsgsMap[msgId];

        //send all the data packets for this message
        uint32_t msgByteLen = outboundSxMsg->msgByteLen;
        simtime_t msgCreationTime = outboundSxMsg->msgCreationTime;
        inet::L3Address destAddr = outboundSxMsg->destAddr;
        inet::L3Address srcAddr = outboundSxMsg->srcAddr;
        uint32_t firstByte = outboundSxMsg->nextByteToSend;
        uint32_t lastByte = 0;
        uint32_t bytesToSend = outboundSxMsg->numBytesToSend;
        
        // uint32_t pktDataBytes = std::min(bytesToSend, maxDataBytesInPkt);
        GrantFields grantFields = rxPkt->getGrantFields();
        uint32_t pktDataBytes = grantFields.grantBytes;
        lastByte = firstByte + pktDataBytes - 1;
        
        // determine whether this is free grant or scheduled grant
        UnschedFields unschedFields;
        SchedDataFields schedFields;
        if(grantFields.isFree){
            unschedFields.firstByte = firstByte;
            unschedFields.lastByte = lastByte;
            unschedFields.msgByteLen = msgByteLen;
            unschedFields.msgCreationTime = msgCreationTime;
            unschedFields.totalUnschedBytes = std::min((int)msgByteLen,freeGrantSize);
        }
        else{
            schedFields.firstByte = firstByte;
            schedFields.lastByte = lastByte;
        }

        bytesToSend -= pktDataBytes;
        firstByte = lastByte + 1;
        outboundSxMsg->nextByteToSend = firstByte;

        // Create a homa pkt for transmission
        HomaPkt* sxPkt = new HomaPkt();
        sxPkt->setSrcAddr(srcAddr);
        sxPkt->setDestAddr(destAddr);
        sxPkt->setMsgId(msgId);
        // sxPkt->setPriority(bytesToSend);
        if(grantFields.isFree){
            sxPkt->setPktType(PktType::UNSCHED_DATA);
            sxPkt->setUnschedFields(unschedFields);
        }
        else{
            sxPkt->setPktType(PktType::SCHED_DATA);
            sxPkt->setSchedDataFields(schedFields);
        }
        sxPkt->setByteLength(pktDataBytes + sxPkt->headerSize());

        // Send the packet out
        socket.sendTo(sxPkt, sxPkt->getDestAddr(), destPort);
    }

}

void
VectioTransport::processDataPkt(HomaPkt* rxPkt)
{
    if(logEvents){
        logFile << simTime() << " Received data pkt for msg: " 
        << rxPkt->getMsgId() << " at the receiver: " << rxPkt->getDestAddr() 
        << " size: " << rxPkt->getDataBytes() << std::endl;
        logFile.flush();
    }
    //////////// TESTING PKT DROPS /////////////////
    // int dropPkt = rand() % 20;
    // if(dropPkt == 0){
    //     logFile << "Sorry, dropping this pkt!!!" << " Msg: " << rxPkt->getMsgId() << std::endl;
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
        if(itr != finishedMsgs.end()){
            auto itr2 = itr->second.find(rxPkt->getSrcAddr());
            if(itr2 != itr->second.end()){
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
        //create and send per-packet grants for the message
        // while(bytesToSend > 0){
        //     uint32_t pktDataBytes = std::min(bytesToSend, this->grantSizeBytes);
        //     HomaPkt* grntPkt = new HomaPkt();
        //     GrantFields grantFields;
        //     grantFields.grantBytes = pktDataBytes;
        //     grantFields.isFree = false;
        //     grntPkt->setSrcAddr(inboundRxMsg->destAddr);
        //     grntPkt->setDestAddr(inboundRxMsg->srcAddr);
        //     grntPkt->setMsgId(inboundRxMsg->msgIdAtSender);
        //     // grntPkt->setPriority(bytesToSend); //TODO think about the priority for grntPkt
        //     grntPkt->setPktType(PktType::GRANT);
        //     grntPkt->setGrantFields(grantFields);
        //     grntPkt->setByteLength(grntPkt->headerSize());
        //     bytesToSend -= pktDataBytes;
        //     assert(bytesToSend >= 0);

        //     // Send the packet out
        //     // outboundGrantQueue.push(grntPkt);
        // };

        //add to pending messages to be granted
        if(bytesToSend > 0){
            auto it = pendingMsgsToGrant.find(inboundRxMsg->msgIdAtSender);
            //make sure that the current Msg doesn't already exist
            if(it != pendingMsgsToGrant.end()){
                for(auto it2 = it->second.begin(); it2 != it->second.end();
                it2++){
                    auto src = it2->first;
                    assert(src != inboundRxMsg->srcAddr);
                }
            }
            //add a new pair to the pendingMsgs
            if(it == pendingMsgsToGrant.end()){
                std::set<std::pair<inet::L3Address,int>> tempSet;
                tempSet.clear();
                tempSet.insert(std::pair<inet::L3Address,int>(
                    inboundRxMsg->srcAddr,bytesToSend));
                pendingMsgsToGrant.insert(std::pair<uint64_t, 
                std::set<std::pair<inet::L3Address,int>>>(
                    inboundRxMsg->msgIdAtSender,tempSet));
            }
            else{
                it->second.insert(std::pair<inet::L3Address,int>(inboundRxMsg->srcAddr,bytesToSend));
            }

            if(!outboundGrantQueueBusy){
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

        //add the msg information to map of finished msgs
        auto itr = finishedMsgs.find(rxPkt->getMsgId());
        if(itr != finishedMsgs.end()){
            auto itr2 = itr->second.find(rxPkt->getSrcAddr());
            assert(itr2 == itr->second.end());
            itr->second.insert(rxPkt->getSrcAddr());
        }
        else{
            std::set<inet::L3Address> newSet;
            newSet.clear();
            newSet.insert(rxPkt->getSrcAddr()); 
            finishedMsgs.insert(
                std::pair<uint64_t,
                std::set<inet::L3Address>>(rxPkt->getMsgId(),newSet));
        }

        logFile << " Msg finished" << std::endl;


        AppMessage* rxMsg = new AppMessage();
        rxMsg->setDestAddr(inboundRxMsg->destAddr);
        rxMsg->setSrcAddr(inboundRxMsg->srcAddr);
        rxMsg->setMsgCreationTime(inboundRxMsg->msgCreationTime);
        rxMsg->setTransportSchedDelay(SIMTIME_ZERO);
        rxMsg->setByteLength(inboundRxMsg->msgByteLen);
        rxMsg->setMsgBytesOnWire(inboundRxMsg->totalBytesOnWire);
        send(rxMsg, "appOut", 0);

        //send an ACK back to sender to delete outboundmsg
        HomaPkt* ackPkt = new HomaPkt();
        ackPkt->setPktType(PktType::ACK);
        ackPkt->setMsgId(msgId);
        ackPkt->setSrcAddr(inboundRxMsg->destAddr);
        ackPkt->setDestAddr(inboundRxMsg->srcAddr);
        socket.sendTo(ackPkt,ackPkt->getDestAddr(),destPort);

        delete inboundRxMsg;

    }
    delete rxPkt;
}


void
VectioTransport::processAckPkt(HomaPkt* rxPkt)
{
    //find the corresponding outbound msg and remove from the map
    auto it = incompleteSxMsgsMap.find(rxPkt->getMsgId());
    logFile << " Msg: " << rxPkt->getMsgId() << std::endl;
    assert(it != incompleteSxMsgsMap.end());
    incompleteSxMsgsMap.erase(it);
    logFile << "Erased flow for msg: " << rxPkt->getMsgId() << std::endl;
    return;
}

void
VectioTransport::processNackPkt(HomaPkt* rxPkt)
{
    logFile << simTime() << " Received NACK pkt" << " Msg: " << rxPkt->getMsgId() << std::endl;
    //check whether the outboundsx msg still exists
    auto itr = incompleteSxMsgsMap.find(rxPkt->getMsgId());
    if(itr != incompleteSxMsgsMap.end()){
        //resend the data packets corresponding to the first and last bytes
        HomaPkt* resendDataPkt = new HomaPkt();
        resendDataPkt->setPktType(PktType::SCHED_DATA);
        int firstByte = rxPkt->getSchedDataFields().firstByte;
        int lastByte = rxPkt->getSchedDataFields().lastByte;
        if(lastByte - firstByte + 1 < grantSizeBytes){
            assert(lastByte + 1 == itr->second->msgByteLen);
        }
        else if(lastByte - firstByte + 1 > grantSizeBytes){
            assert(false);
        }
        resendDataPkt->setMsgId(rxPkt->getMsgId());
        resendDataPkt->setSrcAddr(itr->second->srcAddr);
        resendDataPkt->setDestAddr(itr->second->destAddr);
        SchedDataFields schedFields;
        schedFields.firstByte = firstByte;
        schedFields.lastByte = lastByte;
        resendDataPkt->setSchedDataFields(schedFields);
        socket.sendTo(resendDataPkt, resendDataPkt->getDestAddr(),destPort);
        logFile << simTime() << " Resent pkt: " << firstByte << " " << lastByte << std::endl;
    }
    return;
}

void
VectioTransport::processInboundGrantQueue(){
    if(inboundGrantQueue.empty() != true){
        inboundGrantQueueBusy = true;
        HomaPkt* grntPkt = inboundGrantQueue.front();
        assert(grntPkt->getPktType() == PktType::GRANT);
        processGrantPkt(grntPkt);
        inboundGrantQueue.pop();

        //schedule the next grant queue processing event after transmission time
        //of data packet corresponding to the current grant packet
        double trans_delay = (grntPkt->getGrantFields().grantBytes + grntPkt->headerSize()) * 8.0 /nicBandwidth;
        scheduleAt(simTime() + trans_delay, inboundGrantQueueTimer);
    }
    else{
        inboundGrantQueueBusy = false;
        return;
    }
}

void
VectioTransport::processPendingMsgsToSend(){
    logFile << "inside pending" << std::endl;
    if(pendingMsgsToSend.empty() != true){
        inboundGrantQueueBusy = true;
        HomaPkt* dataPkt = extractDataPkt("SRPT");
        int pktByteLen = 0;
        if(dataPkt->getPktType() == PktType::SCHED_DATA || 
        dataPkt->getPktType() == PktType::UNSCHED_DATA){
            socket.sendTo(dataPkt, dataPkt->getDestAddr(), destPort);
            if(dataPkt->getPktType() == PktType::SCHED_DATA){
                pktByteLen = dataPkt->getSchedDataFields().lastByte - dataPkt->getSchedDataFields().firstByte + 1;
            }
            else if(dataPkt->getPktType() == PktType::UNSCHED_DATA){
                pktByteLen = dataPkt->getUnschedFields().lastByte - dataPkt->getUnschedFields().firstByte + 1;
            }
            else{
                assert(false);
            }
        }
        else{
            //this could happen if the msg was already 
            // done sendig data pkts due to nacks
            // and there is no packet to send
            inboundGrantQueueBusy = false;
            return;
        }

        //schedule the next grant queue processing event after transmission time
        //of data packet corresponding to the current grant packet
        double trans_delay = (pktByteLen + dataPkt->headerSize()) * 8.0 /nicBandwidth;
        scheduleAt(simTime() + trans_delay, inboundGrantQueueTimer);
    }
    else{
        inboundGrantQueueBusy = false;
        return;
    }
}

HomaPkt*
VectioTransport::extractDataPkt(const char* schedulingPolicy){
    logFile << "inside extract" << std::endl;
    if(pendingMsgsToSend.size() == 0){
        //send a null data pkt here
        HomaPkt* nonePkt = new HomaPkt();
        nonePkt->setPktType(PktType::NONE);
        return nonePkt;
    }
    // first check the pendingMsgsToSend
    // find the corresponding msg
    // then check the incompletesxmsgs list
    // if the msg does exist there, fine, else, remove the msg from pendinglsgtosend as well
    // update the bytestosend, if they become zero, update the pendingmsgstosend as well

    //then create a data pkt
    //if no data pkt possible, create a data pkt but make its type to be null
    if(schedulingPolicy == "SRPT"){
        //find the message with the smallest remaining bytes to send first
        int minBytesToSend = INT_MAX;
        uint64_t chosenMsgId;
        auto chosenItr = pendingMsgsToSend.begin();
        bool someMsgToSend = false;
        for(auto itr = pendingMsgsToSend.begin(); itr != pendingMsgsToSend.end(); 
        itr++){
            logFile << " current msg---: " << itr->first << " bytes to send: " << itr->second << std::endl;
            uint64_t messageID = itr->first; 
            int bytesToSend = itr->second;
            if(bytesToSend > 0 && bytesToSend < minBytesToSend){
                chosenMsgId = messageID;
                chosenItr = itr;
                minBytesToSend = bytesToSend;
                someMsgToSend = true;
            }
        }

        if(someMsgToSend == false){
            //no msg has any available grant to send
            logFile << "here" << std::endl;
            HomaPkt* nonePkt = new HomaPkt();
            nonePkt->setPktType(PktType::NONE);
            return nonePkt;
        }
        else if(incompleteSxMsgsMap.find(chosenMsgId) == incompleteSxMsgsMap.end()){
            //remove corresponding msg from pendingMsgsToSend
            pendingMsgsToSend.erase(chosenItr);
            logFile << " here--: erased msg: " << chosenMsgId << std::endl;
            return extractDataPkt(schedulingPolicy);
        }
        else{
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
            
            uint32_t pktByteLen = std::min((uint32_t)grantSizeBytes,(uint32_t)bytesLeftToSend);
            lastByte = firstByte + pktByteLen - 1;
            if(lastByte <= freeGrantSize){
                //send unsched packet
                UnschedFields unschedField;
                unschedField.firstByte = firstByte;
                unschedField.lastByte = lastByte;
                unschedField.msgByteLen = msgByteLen;
                unschedField.msgCreationTime = msgCreationTime;
                unschedField.totalUnschedBytes = std::min((int)msgByteLen,freeGrantSize);
                sxPkt->setPktType(PktType::UNSCHED_DATA);
                sxPkt->setUnschedFields(unschedField);
            }
            else{
                //send sched packet
                SchedDataFields schedField;
                schedField.firstByte = firstByte;
                schedField.lastByte = lastByte;
                sxPkt->setPktType(PktType::SCHED_DATA);
                sxPkt->setSchedDataFields(schedField);
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
    else{
        assert(false);
    }
}

void
VectioTransport::processOutboundGrantQueue(){
    if(outboundGrantQueue.empty() != true){
        outboundGrantQueueBusy = true;
        HomaPkt* grntPkt = outboundGrantQueue.front();
        assert(grntPkt->getPktType() == PktType::GRANT);
        socket.sendTo(grntPkt, grntPkt->getDestAddr(), destPort);
        //update the bytes granted for the inbound msg
        uint64_t msgId = grntPkt->getMsgId();
        inet::L3Address srcAddr = grntPkt->getDestAddr();
        InboundMsg* inboundRxMsg = NULL;
        std::list<InboundMsg*> &rxMsgList = incompleteRxMsgsMap[msgId];
        for(auto inbndIter = rxMsgList.begin(); 
            inbndIter != rxMsgList.end(); ++inbndIter){
            InboundMsg* incompleteRxMsg = *inbndIter;
            ASSERT(incompleteRxMsg->msgIdAtSender == msgId);
            if (incompleteRxMsg->srcAddr == srcAddr) {
                inboundRxMsg = incompleteRxMsg;
                break;
            }
        }

        assert(inboundRxMsg != NULL);
        inboundRxMsg->bytesGranted += grntPkt->getGrantFields().grantBytes;
        logFile << simTime() << " bytes granted: " << inboundRxMsg->bytesGranted << std::endl;

        outboundGrantQueue.pop();

        //schedule the next grant queue processing event after transmission time
        //of data packet corresponding to the current grant packet
        double trans_delay = (grntPkt->getGrantFields().grantBytes + grntPkt->headerSize()) * 8.0 /nicBandwidth;
        scheduleAt(simTime() + trans_delay, outboundGrantQueueTimer);
    }
    else{
        outboundGrantQueueBusy = false;
        return;
    }
}

void
VectioTransport::processPendingMsgsToGrant(){
    if(pendingMsgsToGrant.empty() != true){
        outboundGrantQueueBusy = true;
        HomaPkt* grntPkt = extractGrantPkt("SRPT");
        assert(grntPkt->getPktType() == PktType::GRANT);
        socket.sendTo(grntPkt, grntPkt->getDestAddr(), destPort);
        //update the bytes granted for the inbound msg
        uint64_t msgId = grntPkt->getMsgId();
        inet::L3Address srcAddr = grntPkt->getDestAddr();
        InboundMsg* inboundRxMsg = NULL;
        std::list<InboundMsg*> &rxMsgList = incompleteRxMsgsMap[msgId];
        for(auto inbndIter = rxMsgList.begin(); 
            inbndIter != rxMsgList.end(); ++inbndIter){
            InboundMsg* incompleteRxMsg = *inbndIter;
            ASSERT(incompleteRxMsg->msgIdAtSender == msgId);
            if (incompleteRxMsg->srcAddr == srcAddr) {
                inboundRxMsg = incompleteRxMsg;
                break;
            }
        }

        assert(inboundRxMsg != NULL);
        inboundRxMsg->bytesGranted += grntPkt->getGrantFields().grantBytes;
        logFile << simTime() << " bytes granted: " << inboundRxMsg->bytesGranted << std::endl;

        //schedule the next grant queue processing event after transmission time
        //of data packet corresponding to the current grant packet
        double trans_delay = (grntPkt->getGrantFields().grantBytes + grntPkt->headerSize()) * 8.0 /nicBandwidth;
        scheduleAt(simTime() + trans_delay, outboundGrantQueueTimer);
    }
    else{
        outboundGrantQueueBusy = false;
        return;
    }
}

HomaPkt*
VectioTransport::extractGrantPkt(const char* schedulingPolicy){
    if(schedulingPolicy == "SRPT"){
        //find the msg with smallest remaining bytes to grant first
        int minBytesToGrant = INT_MAX;
        uint64_t chosenMsgId;
        inet::L3Address chosenSrcAddr;
        assert(pendingMsgsToGrant.size() > 0);
        auto chosenItr = pendingMsgsToGrant.begin();
        auto chosenItr2 = chosenItr->second.begin();
        for(auto itr = pendingMsgsToGrant.begin(); itr != pendingMsgsToGrant.end();
        itr++){
            uint64_t messageID = itr->first;
            for(auto itr2 = itr->second.begin(); itr2 != itr->second.end();
            itr2++){
                inet::L3Address messageSrcAddr = itr2->first;
                int bytesToGrant = itr2->second;
                assert(bytesToGrant > 0);
                if(bytesToGrant < minBytesToGrant){
                    chosenMsgId = messageID;
                    chosenSrcAddr = messageSrcAddr;
                    chosenItr = itr;
                    chosenItr2 = itr2;
                    minBytesToGrant = bytesToGrant;
                }
            }
        }
        //create grant packet using the chosen message
        assert(chosenItr == pendingMsgsToGrant.find(chosenMsgId));
        
        uint32_t pktDataBytes = std::min(chosenItr2->second, this->grantSizeBytes);
        HomaPkt* grntPkt = new HomaPkt();
        GrantFields grantFields;
        grantFields.grantBytes = pktDataBytes;
        grantFields.isFree = false;
        grntPkt->setSrcAddr(srcAddress);
        grntPkt->setDestAddr(chosenSrcAddr);
        grntPkt->setMsgId(chosenMsgId);
        // grntPkt->setPriority(bytesToSend); //TODO think about the priority for grntPkt
        grntPkt->setPktType(PktType::GRANT);
        grntPkt->setGrantFields(grantFields);
        grntPkt->setByteLength(grntPkt->headerSize());
        auto remainingBytesToGrant = chosenItr2->second - pktDataBytes;
        chosenItr->second.erase(chosenItr2);
        if(remainingBytesToGrant > 0){
            chosenItr->second.insert(std::pair<inet::L3Address,int>(chosenSrcAddr,remainingBytesToGrant));
        }
        else if(remainingBytesToGrant == 0){
            if(chosenItr->second.size() == 0){
                pendingMsgsToGrant.erase(chosenItr);
            }
        }
        else{
            assert(false);
        }
        return grntPkt;

    }
    else{
        assert(false);    
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
    for(auto inbndIter = rxMsgList.begin(); 
        inbndIter != rxMsgList.end(); ++inbndIter){
        InboundMsg* incompleteRxMsg = *inbndIter;
        ASSERT(incompleteRxMsg->msgIdAtSender == msgId);
        if (incompleteRxMsg->srcAddr == srcAddr) {
            inboundRxMsg = incompleteRxMsg;
            break;
        }
    }

    if(inboundRxMsg != NULL){
        inboundRxMsg->checkAndSendNack();
    }
    else{
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
    if(numBytesToRecv == 0){
        return;
        //assert the message is finished
    }
    else if(bytesGranted < msgByteLen){
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
        if(missedPkts.size() > 0){
            //send a NACK for every missed packet
            for(auto itr=missedPkts.begin(); itr != missedPkts.end(); itr++){
                int missedPktSeqNo = itr->first;
                HomaPkt* nackPkt = new HomaPkt();
                nackPkt->setPktType(PktType::NACK);
                nackPkt->setSrcAddr(destAddr);
                nackPkt->setDestAddr(srcAddr);
                nackPkt->setMsgId(msgIdAtSender);
                SchedDataFields schedFields;
                uint32_t firstByte = missedPktSeqNo * transport->grantSizeBytes;
                uint32_t lastByte = firstByte + transport->grantSizeBytes - 1;
                if(lastByte + 1 > msgByteLen){
                    lastByte = msgByteLen - 1;
                }
                schedFields.firstByte = firstByte;
                schedFields.lastByte = lastByte;
                nackPkt->setSchedDataFields(schedFields);
                transport->socket.sendTo(nackPkt,nackPkt->getDestAddr(),transport->destPort);
                logFile << "Sent nack for missed pkt: " << firstByte << " " << lastByte << " Msg: " << msgIdAtSender << std::endl;
            }
        }
        if(largestByteRcvd < bytesGranted - 1){
            //send a NACK for every last unrcvd packet
            for(int newFirstByte=largestByteRcvd+1; 
            newFirstByte <= bytesGranted-1; 
            newFirstByte = newFirstByte + transport->grantSizeBytes){
                HomaPkt* nackPkt = new HomaPkt();
                nackPkt->setPktType(PktType::NACK);
                nackPkt->setSrcAddr(destAddr);
                nackPkt->setDestAddr(srcAddr);
                nackPkt->setMsgId(msgIdAtSender);
                SchedDataFields schedFields;
                uint32_t firstByte = newFirstByte;
                uint32_t lastByte = firstByte + transport->grantSizeBytes - 1;
                if(lastByte + 1 > bytesGranted){
                    lastByte = bytesGranted - 1;
                }
                schedFields.firstByte = firstByte;
                schedFields.lastByte = lastByte;
                nackPkt->setSchedDataFields(schedFields);
                transport->socket.sendTo(nackPkt,nackPkt->getDestAddr(),transport->destPort);
                logFile << "Sent nack for last missed pkt: " << firstByte << " " << lastByte << " Msg: " << msgIdAtSender << std::endl;
            }
        }

        //create timer for checking again
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
    if(pktSeqNo == largestPktSeqRcvd + 1){
        //no new misses, nothing to do
        return false;
    }
    else if(pktSeqNo > largestPktSeqRcvd + 1){
        // some pkts missed, update  missedPkts
        // create timeout event to later check and send NACK
        for(int i=largestPktSeqRcvd+1; i<pktSeqNo;i++){
            auto itr = missedPkts.find(i);
            assert(itr == missedPkts.end());
            missedPkts.insert(std::pair<int,simtime_t>(i,simTime()));
        }
        return false;
    }
    else if(pktSeqNo <= largestPktSeqRcvd){
        // pkt which was previously missed, update missedPkts
        auto itr = missedPkts.find(pktSeqNo);
        if(itr != missedPkts.end()){
            missedPkts.erase(itr);
            return false;
        }
        else{
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
    if(rxPkt->getPktType() == PktType::SCHED_DATA){
        schedFields = rxPkt->getSchedDataFields();
        dataBytesInPkt =
        schedFields.lastByte - schedFields.firstByte + 1;
        pktSeqNo = schedFields.firstByte / (this->transport)->grantSizeBytes;
        lastByte = schedFields.lastByte;
        logFile << "pkt seq no: " << pktSeqNo << " first: " << 
        schedFields.firstByte << " last: " << schedFields.lastByte << 
        " data: " << dataBytesInPkt << std::endl;
        logFile.flush();
    }
    else{
        assert(rxPkt->getPktType() == PktType::UNSCHED_DATA);
        unschedFields = rxPkt->getUnschedFields();
        dataBytesInPkt =
        unschedFields.lastByte - unschedFields.firstByte + 1;
        pktSeqNo = unschedFields.firstByte / transport->grantSizeBytes;
        lastByte = unschedFields.lastByte;
        logFile << "pkt seq no: " << pktSeqNo << " first: " << 
        unschedFields.firstByte << " last: " << unschedFields.lastByte << 
        " data: " << dataBytesInPkt << std::endl;
        logFile.flush();
    }
    ASSERT((rxPkt->getSrcAddr() == srcAddr) &&
            (rxPkt->getDestAddr() == destAddr) &&
            (rxPkt->getMsgId() == msgIdAtSender));

    bool isPktDuplicate = updateRxAndMissedPkts(pktSeqNo);

    //update the largest received pkt seqno
    if(pktSeqNo > largestPktSeqRcvd){
        largestPktSeqRcvd = pktSeqNo;
        assert(lastByte > largestByteRcvd);
        largestByteRcvd = lastByte;
    }

    // Return true if rxPkt is the sole packet of a size zero message
    // if (msgByteLen == 0) {
    //     totalBytesOnWire +=
    //         HomaPkt::getBytesOnWire(0, (PktType)rxPkt->getPktType());
    //     return true;
    // }

    // append the data and return
    // totalBytesOnWire +=
    //     HomaPkt::getBytesOnWire(dataBytesInPkt, (PktType)rxPkt->getPktType());

    if(!isPktDuplicate){
        numBytesToRecv -= dataBytesInPkt;
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
