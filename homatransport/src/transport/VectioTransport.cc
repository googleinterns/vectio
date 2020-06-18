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
#include "VectioTransport.h"

Define_Module(VectioTransport);

std::ofstream logFile;

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

    std::string LogFileName = std::string(
                "results/") + std::string(par("logFile").stringValue());
    if(!logFile.is_open()) {
        logFile.open(LogFileName);
    }

    logEvents = par("logEvents");
}

void
VectioTransport::processStart()
{
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
            default:
                throw cRuntimeError("Received SelfMsg of type(%d) is not valid.",
                        msg->getKind());
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
    //Receive message from the app, store the outbound message state and 
    // send out a request packet
    uint32_t msgByteLen = sendMsg->getByteLength();
    simtime_t msgCreationTime = sendMsg->getMsgCreationTime();
    inet::L3Address destAddr = sendMsg->getDestAddr();
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

    //Create an outbound message, and add it to the list of outbound messages
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

    //Create and forward a request packet for this outbound message
    uint32_t pktDataBytes = 1;
    lastByte = firstByte + pktDataBytes - 1;
    UnschedFields unschedFields;
    unschedFields.msgByteLen = msgByteLen;
    unschedFields.msgCreationTime = msgCreationTime;
    unschedFields.totalUnschedBytes = pktDataBytes;
    unschedFields.firstByte = firstByte;
    unschedFields.lastByte = lastByte;
    bytesToSend -= pktDataBytes;
    firstByte = lastByte + 1;

    HomaPkt* rqPkt = new HomaPkt();
    rqPkt->setSrcAddr(srcAddr);
    rqPkt->setDestAddr(destAddr);
    rqPkt->setMsgId(msgId);
    // rqPkt->setPriority(bytesToSend); //TODO think about priority for rqpkt
    rqPkt->setPktType(PktType::REQUEST);
    rqPkt->setUnschedFields(unschedFields);
    rqPkt->setByteLength(pktDataBytes + rqPkt->headerSize());

    // Send the packet out
    socket.sendTo(rqPkt, rqPkt->getDestAddr(), destPort);

    delete sendMsg;
    ++msgId;
}

void
VectioTransport::processRcvdPkt(HomaPkt* rxPkt)
{
    //Parse the received packet -- whetehr it's REQUEST, GRANT or DATA pkt
    switch (rxPkt->getPktType()) {
        case PktType::REQUEST:
            processReqPkt(rxPkt);
            break;
        case PktType::UNSCHED_DATA:
        case PktType::SCHED_DATA:
            processDataPkt(rxPkt);
            break;
        case PktType::GRANT:
            processGrantPkt(rxPkt);
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
        logFile << simTime() << " Received request pkt for msg: " << 
        rxPkt->getMsgId() << " at the receiver: " << 
        rxPkt->getDestAddr() << std::endl;
        logFile.flush();
    }

    // Request pkt for a message received at the receiver 
    // Add the message to the map of flows to be received
    // Send grant packet to the sender for receiving the corresponding flow

    //make sure the message doesn't already exist in the map
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
    assert(!inboundRxMsg);

    //add the message to the map
    if(!inboundRxMsg){
        inboundRxMsg = new InboundMsg(rxPkt); 
        //TODO make sure the correct information is transferred here
        rxMsgList.push_front(inboundRxMsg);
    }
    else{
        assert(false);
    }

    //create and send a grant message for the added message
    HomaPkt* grntPkt = new HomaPkt();
    grntPkt->setSrcAddr(inboundRxMsg->destAddr);
    grntPkt->setDestAddr(inboundRxMsg->srcAddr);
    grntPkt->setMsgId(inboundRxMsg->msgIdAtSender);
    // grntPkt->setPriority(bytesToSend);//TODO think about priority for grntPkt
    grntPkt->setPktType(PktType::GRANT);
    // grntPkt->setUnschedFields(unschedFields);
    // grntPkt->setByteLength(pktDataBytes + grntPkt->headerSize());

    // Send the packet out
    socket.sendTo(grntPkt, grntPkt->getDestAddr(), destPort);

    //TODO how to set the bytes allowed by a grant packet
}

void
VectioTransport::processGrantPkt(HomaPkt* rxPkt)
{
    if(logEvents){
        logFile << simTime() << " Received grant pkt for msg: " << 
        rxPkt->getMsgId() << " at the sender: " << 
        rxPkt->getDestAddr() << std::endl;
        logFile.flush();
    }
    // Grant pkt for a message received at the sender
    // Send the data packets corresponding to the message
    // Remove the message from the map once done sending all the packets
    uint64_t msgId = rxPkt->getMsgId();

    //make sure the msg exists in the map
    assert(incompleteSxMsgsMap.find(msgId) != incompleteSxMsgsMap.end());
    OutboundMsg* outboundSxMsg = incompleteSxMsgsMap[msgId];

    //send all the data packets for this message
    uint32_t msgByteLen = outboundSxMsg->msgByteLen;
    simtime_t msgCreationTime = outboundSxMsg->msgCreationTime;
    inet::L3Address destAddr = outboundSxMsg->destAddr;
    inet::L3Address srcAddr = outboundSxMsg->srcAddr;
    uint32_t firstByte = 0;
    uint32_t lastByte = 0;
    uint32_t bytesToSend = msgByteLen;
    do{
        // Create a scheduled pkt and fill it up with the proper parameters
        uint32_t pktDataBytes = std::min(bytesToSend, maxDataBytesInPkt);
        lastByte = firstByte + pktDataBytes - 1;
        SchedDataFields schedFields;
        schedFields.firstByte = firstByte;
        schedFields.lastByte = lastByte;
        bytesToSend -= pktDataBytes;
        firstByte = lastByte + 1;

        // Create a homa pkt for transmission
        HomaPkt* sxPkt = new HomaPkt();
        sxPkt->setSrcAddr(srcAddr);
        sxPkt->setDestAddr(destAddr);
        sxPkt->setMsgId(msgId);
        // sxPkt->setPriority(bytesToSend);
        sxPkt->setPktType(PktType::SCHED_DATA);
        sxPkt->setSchedDataFields(schedFields);
        sxPkt->setByteLength(pktDataBytes + sxPkt->headerSize());

        // Send the packet out
        socket.sendTo(sxPkt, sxPkt->getDestAddr(), destPort);
    }while(bytesToSend > 0);

    //remove the message from the map
    auto it = incompleteSxMsgsMap.find(msgId);
    assert(it != incompleteSxMsgsMap.end());
    incompleteSxMsgsMap.erase(it);

}

void
VectioTransport::processDataPkt(HomaPkt* rxPkt)
{
    if(logEvents){
        logFile << simTime() << " Received data pkt for msg: " << 
        rxPkt->getMsgId() << " at the receiver: " << 
        rxPkt->getDestAddr() << std::endl;
        logFile.flush();
    }
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
       assert(false);
       //This should never happen cause the map had already been updated when 
       // received the grant, and would be removed only after 
       // receiving all the packets
    }

    // Append the data to the inboundRxMsg and if the msg is complete, remove it
    // from the list of outstanding messages in the map, and send the complete
    // message to the application.
    if (inboundRxMsg->appendPktData(rxPkt)) {
        rxMsgList.remove(inboundRxMsg);
        if (rxMsgList.empty()) {
            incompleteRxMsgsMap.erase(msgId);
        }
        AppMessage* rxMsg = new AppMessage();
        rxMsg->setDestAddr(inboundRxMsg->destAddr);
        rxMsg->setSrcAddr(inboundRxMsg->srcAddr);
        rxMsg->setMsgCreationTime(inboundRxMsg->msgCreationTime);
        rxMsg->setTransportSchedDelay(SIMTIME_ZERO);
        rxMsg->setByteLength(inboundRxMsg->msgByteLen);
        rxMsg->setMsgBytesOnWire(inboundRxMsg->totalBytesOnWire);
        send(rxMsg, "appOut", 0);
        delete inboundRxMsg;
    }
    delete rxPkt;
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

VectioTransport::InboundMsg::InboundMsg(HomaPkt* rxPkt)
    : numBytesToRecv(0)
    , msgByteLen(0)
    , totalBytesOnWire(0)
    , srcAddr(rxPkt->getSrcAddr())
    , destAddr(rxPkt->getDestAddr())
    , msgIdAtSender(rxPkt->getMsgId())
    , msgCreationTime(SIMTIME_ZERO)
{
    numBytesToRecv = rxPkt->getUnschedFields().msgByteLen;
    msgByteLen = numBytesToRecv;
    msgCreationTime = rxPkt->getUnschedFields().msgCreationTime;
}

VectioTransport::InboundMsg::~InboundMsg()
{}

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
    SchedDataFields schedFields = rxPkt->getSchedDataFields();
    ASSERT((rxPkt->getPktType() == PktType::SCHED_DATA)
            );
    ASSERT((rxPkt->getSrcAddr() == srcAddr) &&
            (rxPkt->getDestAddr() == destAddr) &&
            (rxPkt->getMsgId() == msgIdAtSender));

    // Return true if rxPkt is the sole packet of a size zero message
    if (msgByteLen == 0) {
        totalBytesOnWire +=
            HomaPkt::getBytesOnWire(0, (PktType)rxPkt->getPktType());
        return true;
    }

    // append the data and return
    uint32_t dataBytesInPkt =
        schedFields.lastByte - schedFields.firstByte + 1;
    totalBytesOnWire +=
        HomaPkt::getBytesOnWire(dataBytesInPkt, (PktType)rxPkt->getPktType());

    numBytesToRecv -= dataBytesInPkt;
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
