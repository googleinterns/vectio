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
#include "VectioSenderTransport.h"
#include "inet/networklayer/common/L3AddressResolver.h"
#include "inet/networklayer/common/InterfaceEntry.h"
#include "inet/networklayer/common/InterfaceTable.h"
#include "inet/networklayer/ipv4/IPv4InterfaceData.h"

Define_Module(VectioSenderTransport);

extern std::ofstream logFile;
extern std::ofstream logFile2;
extern bool logPacketEvents;

VectioSenderTransport::VectioSenderTransport()
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

VectioSenderTransport::~VectioSenderTransport()
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
VectioSenderTransport::initialize()
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

    maxWindSize = 1.1 * allowedInFlightGrantedBytes;
    minWindSize = (int) (0.125 * ((double)(allowedInFlightGrantedBytes)));

    nicLinkSpeed = par("nicLinkSpeed").longValue();
    fabricLinkSpeed = par("fabricLinkSpeed").longValue();
    edgeLinkDelay = 1e-6 * par("edgeLinkDelay").doubleValue();
    fabricLinkDelay = 1e-6 * par("fabricLinkDelay").doubleValue();
    hostSwTurnAroundTime = 1e-6 * par("hostSwTurnAroundTime").doubleValue();
    hostNicSxThinkTime = 1e-6 * par("hostNicSxThinkTime").doubleValue();
    switchFixDelay = 1e-6 * par("switchFixDelay").doubleValue();
    isFabricCutThrough = par("isFabricCutThrough").boolValue();
    isSingleSpeedFabric = par("isSingleSpeedFabric").boolValue();

    srand(1);
}

void
VectioSenderTransport::processStart()
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
VectioSenderTransport::processStop()
{}

void
VectioSenderTransport::finish()
{}

void
VectioSenderTransport::handleMessage(cMessage *msg)
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
                // processPendingMsgsToAck();
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
VectioSenderTransport::processMsgFromApp(AppMessage* sendMsg)
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

    delete sendMsg;

    // Create free grants and push them to the outboundGrantsQueue
    int bytesToGrant = (int)msgByteLen;

    assert(pendingMsgsToSend.find(
        outboundSxMsg->msgIdAtSender) == pendingMsgsToSend.end());
    pendingMsgsToSend.insert(
        std::pair<uint64_t,int>(outboundSxMsg->msgIdAtSender,bytesToGrant));

    if(windPerDest.find(destAddr) == windPerDest.end()){
        if(destAddr.toIPv4().getDByte(2) == srcAddr.toIPv4().getDByte(2)){
            windPerDest.insert(std::pair<inet::L3Address, int>(destAddr, allowedInFlightGrantedBytesIntraPod));
        }
        else{
            windPerDest.insert(std::pair<inet::L3Address, int>(destAddr, allowedInFlightGrantedBytes));
        }
    }

    if (!inboundGrantQueueBusy){
        processPendingMsgsToSend();
    }
}

void
VectioSenderTransport::processRcvdPkt(HomaPkt* rxPkt)
{
    // Parse the received packet -- whetehr it's REQUEST, ACK or DATA pkt
    switch (rxPkt->getPktType()) {
        case PktType::REQUEST:
            assert(false);
            break;
        case PktType::UNSCHED_DATA:
        case PktType::SCHED_DATA:
            processDataPkt(rxPkt);
            break;
        case PktType::GRANT:
            assert(false);
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
VectioSenderTransport::processDataPkt(HomaPkt* rxPkt)
{
    if (logEvents && rxPkt->getMsgId() == 288) {
        logFile << simTime() << " Received data pkt for msg: " 
        << rxPkt->getMsgId() << " at the receiver: " << rxPkt->getDestAddr() 
        << " size: " << rxPkt->getDataBytes() << " scheduled at: " 
        << std::endl;
        logFile.flush();
    }

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
        int alreadyGrantedBytes = inboundRxMsg->msgByteLen;
        assert(alreadyGrantedBytes <= bytesToSend);
        bytesToSend -= alreadyGrantedBytes;
        inboundRxMsg->bytesGranted = alreadyGrantedBytes;

        inboundRxMsg->firstPktSchedTime = rxPkt->pktScheduleTime;

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

        // // send an ACK back to sender to delete outboundmsg
        // HomaPkt* ackPkt = new HomaPkt();
        // ackPkt->setPktType(PktType::ACK);
        // ackPkt->setMsgId(msgId);
        // ackPkt->setSrcAddr(inboundRxMsg->destAddr);
        // ackPkt->setDestAddr(inboundRxMsg->srcAddr);
        // ackPkt->setPriority(0);
        // socket.sendTo(ackPkt,ackPkt->getDestAddr(),destPort);

        delete inboundRxMsg;

    }
    delete rxPkt;
}


void
VectioSenderTransport::processAckPkt(HomaPkt* rxPkt)
{   
    SchedDataFields schedFields;
    schedFields = rxPkt->getSchedDataFields();
    int pktBytes = schedFields.lastByte - schedFields.firstByte + 1;
    // find the corresponding outbound msg and remove from the map
    auto it = incompleteSxMsgsMap.find(rxPkt->getMsgId());
    assert(it != incompleteSxMsgsMap.end());
    
    it->second->bytesAcked += pktBytes;
    assert(it->second->bytesAcked <= it->second->msgByteLen);
    // logFile << simTime() << " received ack: " << schedFields.firstByte << " " << schedFields.lastByte << " bytes acked: " << it->second->bytesAcked << " len: " << it->second->msgByteLen << std::endl;
    if(it->second->bytesAcked == it->second->msgByteLen){
        incompleteSxMsgsMap.erase(it);
        if (logEvents) {
            logFile << "Erased flow for msg: " << rxPkt->getMsgId() << std::endl;
        }
    }

    currentRtt = ((simTime() - rxPkt->getTimestamp()).dbl() * 2.0);
    auto currRttItr = currRttPerReceiver.find(rxPkt->getSrcAddr());
    if(currRttItr == currRttPerReceiver.end()){
        currRttPerReceiver.insert(std::pair<inet::L3Address,double>(rxPkt->getSrcAddr(),currentRtt));
        assert(targetDelayPerReceiver.find(rxPkt->getSrcAddr()) == targetDelayPerReceiver.end());
        targetDelayPerReceiver.insert(std::pair<inet::L3Address,double>(rxPkt->getSrcAddr(),calculateTargetDelay(rxPkt->getSrcAddr(),rxPkt->getDestAddr())));
    }
    else{
        currRttItr->second = currentRtt;
        // logFile << simTime() << " currRtt: " << currentRtt << " target: " << targetDelayPerReceiver.find(rxPkt->getSrcAddr())->second << std::endl; 
        assert(targetDelayPerReceiver.find(rxPkt->getSrcAddr()) != targetDelayPerReceiver.end());
    }

    adjustWindSize(rxPkt->getSrcAddr(), pktBytes);

    assert(receiverInFlightBytes.find(rxPkt->getSrcAddr()) !=
    receiverInFlightBytes.end());
    auto itr = receiverInFlightBytes.find(rxPkt->getSrcAddr());
    // logFile << simTime() << " itr->second: " << itr->second << " " << pktBytes << std::endl;

    assert(itr->second >= pktBytes);
    
    itr->second -= pktBytes;
    assert(itr->second >= 0);
    currentSenderInFlightBytes -= pktBytes;
    assert(currentSenderInFlightBytes >= 0);


    delete rxPkt;

    return;
}

void
VectioSenderTransport::processNackPkt(HomaPkt* rxPkt)
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
VectioSenderTransport::processPendingMsgsToSend(){
    // logFile << simTime() << " in here: " << sendQueueBusy << " " << inboundGrantQueueBusy << " " << pendingMsgsToSend.empty() << std::endl;
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
                // logFile << simTime() << " no pkt retured" << std::endl;
                // inboundGrantQueueBusy = false;
                double trans_delay_temp = (grantSizeBytes + 100) * 8.0 /nicBandwidth; 
                scheduleAt(simTime() + trans_delay_temp + INFINITISIMALTIME, inboundGrantQueueTimer);
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
VectioSenderTransport::extractDataPkt(const char* schedulingPolicy){
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

        if (currentSenderInFlightBytes > (int) (degOverComm * 
        allowedInFlightGrantedBytes)){
            //receiver already exceeded the allowed inflight byte limit
            HomaPkt* nonePkt = new HomaPkt();
            nonePkt->setPktType(PktType::NONE);
            return nonePkt;
        }

        std::set<inet::L3Address> receiversToExclude;
        receiversToExclude.clear();

        uint64_t chosenMsgId;
        inet::L3Address chosenDestAddr;
        assert(pendingMsgsToSend.size() > 0);
        auto chosenItr = pendingMsgsToSend.begin();

        uint16_t assignedPrio = 2;

        do{

            // find the message with the smallest remaining bytes to send first
            int minBytesToSend = INT_MAX;
            int minMsgBytesRemaining = INT_MAX;
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
                    inet::L3Address messageDestAddr = 
                    incompleteSxMsgsMap[messageID]->destAddr;
                    assert(bytesToSend > 0);
                    assert(msgBytesRemaining > 0);
                    if (logEvents && messageID == 288){
                        logFile << simTime() << " bts: " << bytesToSend 
                        << " msgbrem: " << msgBytesRemaining  << "id: " << messageID << std::endl;
                    }
                    assert(bytesToSend <= msgBytesRemaining);

                    if (msgBytesRemaining < minMsgBytesRemaining &&  
                    receiversToExclude.find(messageDestAddr) == 
                    receiversToExclude.end()){
                        chosenMsgId = messageID;
                        chosenItr = itr;
                        chosenDestAddr = incompleteSxMsgsMap[messageID]->destAddr;
                        minBytesToSend = bytesToSend;
                        someMsgToSend = true;
                        minCreationTime = 
                        incompleteSxMsgsMap[messageID]->msgCreationTime;
                        minMsgBytesRemaining = msgBytesRemaining;
                    }
                    else if (msgBytesRemaining == minMsgBytesRemaining &&  
                    receiversToExclude.find(messageDestAddr) == 
                    receiversToExclude.end()){
                        if (incompleteSxMsgsMap[messageID]->msgCreationTime.dbl() < 
                        minCreationTime.dbl()){
                            chosenMsgId = messageID;
                            chosenItr = itr;
                            chosenDestAddr = incompleteSxMsgsMap[messageID]->destAddr;
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

            // logFile << simTime() << " finally chosen: " << chosenMsgId << std::endl;

            if(receiverInFlightBytes.find(chosenDestAddr) ==
            receiverInFlightBytes.end()){
                receiverInFlightBytes.insert(std::pair<inet::L3Address,int>(chosenDestAddr,0));
            }
            assert(receiverInFlightBytes.find(chosenDestAddr) !=
            receiverInFlightBytes.end());
            auto receiverBytesItr = receiverInFlightBytes.find(chosenDestAddr);

            if (receiverBytesItr->second > windPerDest.find(chosenDestAddr)->second){
                receiversToExclude.insert(chosenDestAddr);
                assignedPrio++;
            }
            else{
                break;
            }


            
        }while(1);

            //also update the senderinflight bytes here now, i guess there was no need for them to be updated here

            OutboundMsg* outboundSxMsg = incompleteSxMsgsMap[chosenMsgId];
            if(assignedPrio > 7){
                assignedPrio = 7;
            }
            outboundSxMsg->schedPrio = assignedPrio;

            uint32_t msgByteLen = outboundSxMsg->msgByteLen;
            simtime_t msgCreationTime = outboundSxMsg->msgCreationTime;
            inet::L3Address destAddr = outboundSxMsg->destAddr;
            inet::L3Address srcAddr = outboundSxMsg->srcAddr;
            uint32_t firstByte = outboundSxMsg->nextByteToSend;
            uint32_t lastByte = 0;

            int bytesLeftToSend = chosenItr->second;
            // assert(bytesLeftToSend == chosenItr->second);
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

            if(bytesLeftToSend == 0){
                pendingMsgsToSend.erase(pendingMsgsToSend.find(chosenMsgId));
            }

            receiverInFlightBytes.find(chosenDestAddr)->second += pktByteLen;
            currentSenderInFlightBytes += pktByteLen;

            return sxPkt;
        
    }
    else {
        assert(false);
    }
}

void
VectioSenderTransport::processSendQueue(){
    if (sendQueue.empty() == true){
        sendQueueBusy = false;
        return;
    }
    else{
        sendQueueBusy = true;
        HomaPkt* sxPkt = sendQueue.front();
        sendQueue.pop();
        int pktBytes = 0;
        sxPkt->setTimestamp(simTime());
        if (sxPkt->getPktType() == PktType::UNSCHED_DATA){
            pktBytes = sxPkt->getUnschedFields().lastByte - sxPkt->getUnschedFields().firstByte + 1;
        }
        else if (sxPkt->getPktType() == PktType::SCHED_DATA){
            pktBytes = sxPkt->getSchedDataFields().lastByte - sxPkt->getSchedDataFields().firstByte + 1;
        }
        else if (sxPkt->getPktType() == PktType::ACK){
            pktBytes = sxPkt->getByteLength();
            // logFile << " length for grant pkt = " << pktBytes << std::endl;
        }
        totalSendQueueSizeInBytes -= (pktBytes);
        assert(totalSendQueueSizeInBytes >= 0);
        // logFile << simTime() << " pkt into socket" << std::endl;
        socket.sendTo(sxPkt,sxPkt->getDestAddr(),localPort);
        double trans_delay = (pktBytes + 100) * 8.0 /nicBandwidth;
        scheduleAt(simTime() + trans_delay, sendQueueTimer);
        return;
    }
}

void
VectioSenderTransport::processRetxTimer(TimerContext* timerContext)
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

VectioSenderTransport::InboundMsg::InboundMsg()
    : numBytesToRecv(0)
    , msgByteLen(0)
    , totalBytesOnWire(0)
    , srcAddr()
    , destAddr()
    , msgIdAtSender(0)
    , msgCreationTime(SIMTIME_ZERO)
{}

VectioSenderTransport::InboundMsg::InboundMsg(HomaPkt* rxPkt, VectioSenderTransport* transport)
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

VectioSenderTransport::InboundMsg::~InboundMsg()
{}

void
VectioSenderTransport::InboundMsg::checkAndSendNack()
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
VectioSenderTransport::InboundMsg::updateRxAndMissedPkts(int pktSeqNo)
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

VectioSenderTransport::OutboundMsg::OutboundMsg()
    : msgByteLen(0)
    , totalBytesOnWire(0)
    , srcAddr()
    , destAddr()
    , msgIdAtSender(0)
    , msgCreationTime(SIMTIME_ZERO)
{}

VectioSenderTransport::OutboundMsg::~OutboundMsg()
{}

bool
VectioSenderTransport::InboundMsg::appendPktData(HomaPkt* rxPkt)
{   
    SchedDataFields schedFields;
    UnschedFields unschedFields;
    uint32_t dataBytesInPkt;
    int firstByte;
    int lastByte;
    int pktSeqNo;
    if (rxPkt->getPktType() == PktType::SCHED_DATA) {
        schedFields = rxPkt->getSchedDataFields();
        dataBytesInPkt =
        schedFields.lastByte - schedFields.firstByte + 1;
        pktSeqNo = schedFields.firstByte / (this->transport)->grantSizeBytes;
        lastByte = schedFields.lastByte;
        firstByte = schedFields.firstByte;
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
        firstByte = unschedFields.firstByte;
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

        // send the ACK here
        // make sure to properly pace the send queue

        if (transport->sendQueueBusy == false){
            assert(transport->totalSendQueueSizeInBytes == 0);
        }
        // grant pkts can be pushed into the sendqueue even if it is non empty
        // since they are higher priority than data pkts
        HomaPkt* ackPkt = new HomaPkt();
        ackPkt->setPktType(PktType::ACK);
        ackPkt->setMsgId(rxPkt->getMsgId());
        ackPkt->setSrcAddr(rxPkt->getDestAddr());
        ackPkt->setDestAddr(rxPkt->getSrcAddr());
        ackPkt->setPriority(0);
        SchedDataFields schedFields;
        schedFields.firstByte = firstByte;
        schedFields.lastByte = lastByte;
        ackPkt->setSchedDataFields(schedFields);
        transport->totalSendQueueSizeInBytes += (ackPkt->getByteLength());
        if (transport->sendQueueBusy == false){
            transport->sendQueueFreeTime = simTime() + ((ackPkt->getByteLength() + 100) * 8.0 
            / transport->nicBandwidth);
            ackPkt->setTimestamp(simTime());
        }
        else{
            transport->sendQueueFreeTime = transport->sendQueueFreeTime + ((ackPkt->getByteLength() + 100)
             * 8.0 / transport->nicBandwidth);
            ackPkt->setTimestamp(transport->sendQueueFreeTime);
        }
        transport->sendQueue.push(ackPkt);

        if (transport->sendQueueBusy == false){
            transport->processSendQueue();
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

double
VectioSenderTransport::calculateTargetDelay(inet::L3Address sAddr, inet::L3Address dAddr){
    int totalBytesTranmitted = 0;
    inet::L3Address srcAddr = sAddr;
    ASSERT(srcAddr.getType() == inet::L3Address::AddressType::IPv4);
    inet::L3Address destAddr = dAddr;
    ASSERT(destAddr.getType() == inet::L3Address::AddressType::IPv4);

    if (destAddr == srcAddr) {
        // no switching delay
        return totalBytesTranmitted;
    }

    // calculate the total transmitted bytes in the the network for this
    // rcvdMsg. These bytes include all headers and ethernet overhead bytes per
    // frame.
    int lastPartialFrameLen = 0;
    int numFullEthFrame = 1;
    uint32_t lastPartialFrameData =
            0;

    totalBytesTranmitted = numFullEthFrame *
            (grantSizeBytes + 100 + ETHERNET_HDR_SIZE +
            ETHERNET_CRC_SIZE + ETHERNET_PREAMBLE_SIZE + INTER_PKT_GAP);

    if (lastPartialFrameData == 0) {
        if (numFullEthFrame == 0) {
            totalBytesTranmitted = MIN_ETHERNET_FRAME_SIZE +
                    ETHERNET_PREAMBLE_SIZE + INTER_PKT_GAP;
            lastPartialFrameLen = totalBytesTranmitted;
        }

    } else {
        if (lastPartialFrameData < (MIN_ETHERNET_PAYLOAD_BYTES -
                IP_HEADER_SIZE - UDP_HEADER_SIZE)) {
            lastPartialFrameLen = MIN_ETHERNET_FRAME_SIZE +
                    ETHERNET_PREAMBLE_SIZE + INTER_PKT_GAP;
        } else {
            lastPartialFrameLen = lastPartialFrameData + IP_HEADER_SIZE
                    + UDP_HEADER_SIZE + ETHERNET_HDR_SIZE + ETHERNET_CRC_SIZE
                    + ETHERNET_PREAMBLE_SIZE + INTER_PKT_GAP;
        }
        totalBytesTranmitted += lastPartialFrameLen;
    }

    double msgSerializationDelay =
            1e-9 * ((totalBytesTranmitted << 3) * 1.0 / nicLinkSpeed);
    // logFile << " total bytes: " << totalBytesTranmitted << " " <<  " msgdelay: " << msgSerializationDelay << std::endl;

    // There's always two hostSwTurnAroundTime and one nicThinkTime involved
    // in ideal latency for the overhead.
    double hostDelayOverheads = 2 * hostSwTurnAroundTime + hostNicSxThinkTime;
    // logFile << " hostdelay: " << hostDelayOverheads << std::endl;

    // Depending on if the switch model is store-forward (omnet++ default model)
    // or cutthrough (as we implemented), the switch serialization delay would
    // be different. The code snipet below finds how many switch a packet passes
    // through and adds the correct switch delay to total delay based on the
    // switch model.
    double totalSwitchDelay = 0;

    double edgeSwitchFixDelay = switchFixDelay;
    double fabricSwitchFixDelay = switchFixDelay;
    double edgeSwitchSerialDelay = 0;
    double fabricSwitchSerialDelay = 0;

    if (numFullEthFrame != 0) {
        edgeSwitchSerialDelay +=
                (grantSizeBytes + 100 + ETHERNET_HDR_SIZE +
                ETHERNET_CRC_SIZE + ETHERNET_PREAMBLE_SIZE + INTER_PKT_GAP) *
                1e-9 * 8 / nicLinkSpeed;

        fabricSwitchSerialDelay += (grantSizeBytes + 100 +
                ETHERNET_HDR_SIZE + ETHERNET_CRC_SIZE + ETHERNET_PREAMBLE_SIZE +
                INTER_PKT_GAP) * 1e-9 * 8 / fabricLinkSpeed;
    } else {
        edgeSwitchSerialDelay += lastPartialFrameLen * 1e-9 * 8 / nicLinkSpeed;
        fabricSwitchSerialDelay +=
                lastPartialFrameLen * 1e-9 * 8 / fabricLinkSpeed;
    }

    if (destAddr.toIPv4().getDByte(2) == srcAddr.toIPv4().getDByte(2)) {

        // src and dest in the same rack
        totalSwitchDelay = edgeSwitchFixDelay;
        if (!isFabricCutThrough) {
            totalSwitchDelay =+ edgeSwitchSerialDelay;
        }

        // Add 2 edge link delays
        totalSwitchDelay += (2 * edgeLinkDelay);
        // logFile << " switchdelay1: " << totalSwitchDelay << std::endl;

    } else if (destAddr.toIPv4().getDByte(1) == srcAddr.toIPv4().getDByte(1)) {

        // src and dest in the same pod
        totalSwitchDelay =
                edgeSwitchFixDelay +  fabricSwitchFixDelay + edgeSwitchFixDelay;
        if (!isFabricCutThrough) {
            totalSwitchDelay +=
                    (2*fabricSwitchSerialDelay + edgeSwitchSerialDelay);
        } else if (!isSingleSpeedFabric) {
            // have cutthrough but forwarding a packet coming from low
            // speed port to high speed port. There will inevitably be one
            // serialization at low speed.
            totalSwitchDelay += edgeSwitchSerialDelay;
        }

        // Add 2 edge link delays and two fabric link delays
        totalSwitchDelay += (2 * edgeLinkDelay + 2 * fabricLinkDelay);
        // logFile << " switchdelay2: " << totalSwitchDelay << std::endl;


    } else {
        totalSwitchDelay = edgeSwitchFixDelay +
                           fabricSwitchFixDelay +
                           fabricSwitchFixDelay +
                           fabricSwitchFixDelay +
                           edgeSwitchFixDelay;
        if (!isFabricCutThrough) {
            totalSwitchDelay += (fabricSwitchSerialDelay +
                    fabricSwitchSerialDelay + fabricSwitchSerialDelay +
                    fabricSwitchSerialDelay + edgeSwitchSerialDelay);
        } else if (!isSingleSpeedFabric) {

            totalSwitchDelay += edgeSwitchFixDelay;
        }

        // Add 2 edge link delays and 4 fabric link delays
        totalSwitchDelay += (2 * edgeLinkDelay + 4 * fabricLinkDelay);
        // logFile << " switchdelay3: " << totalSwitchDelay << std::endl;

    }


    return queueingDelayFactor * 2 * (msgSerializationDelay + totalSwitchDelay + hostDelayOverheads);
}

void
VectioSenderTransport::adjustWindSize(inet::L3Address dAddr, int pktSize){
    // implement the congestion control logic here

    assert(currRttPerReceiver.find(dAddr) != currRttPerReceiver.end());
    double currRtt = currRttPerReceiver.find(dAddr)->second;
    assert(targetDelayPerReceiver.find(dAddr) != targetDelayPerReceiver.end());
    double targetDelay = targetDelayPerReceiver.find(dAddr)->second;
    assert(windPerDest.find(dAddr) != windPerDest.end());
    auto curWind = windPerDest.find(dAddr)->second;
    int newWind = curWind;

    if(currRtt < targetDelay){
        newWind = curWind + ((int)(((double)(ai) * (double)(pktSize))));
        newWind = std::min(maxWindSize, newWind);
        // logFile << simTime() << " cur wind: " << curWind << " increased cwnd: " << newWind << " max: " << maxWindSize << std::endl;
    }
    else{
        double redFactor = (md * ((currRtt/targetDelay) - 1));
        newWind = (int)(((double)(curWind)) *  (1.0 - redFactor));
        newWind = std::max(minWindSize, newWind);
        assert(newWind <= curWind);
        // window only reduced once per RTT
        if(lastReducedWind.find(dAddr) == lastReducedWind.end()){
            lastReducedWind.insert(std::pair<inet::L3Address,simtime_t>(dAddr,simTime()));
            // logFile << simTime() << " reduced1 cwnd: " << newWind << std::endl;
        }
        else{
            auto lastReducedTime = lastReducedWind.find(dAddr)->second;
            assert(simTime().dbl() - lastReducedTime.dbl() >= 0);
            if(simTime().dbl() - lastReducedTime.dbl() < baseRtt){
                newWind = curWind;
                //not changed in this case
            }
            else{
                lastReducedWind.find(dAddr)->second = simTime();
                // logFile << simTime() << " reduced2 cwnd: " << newWind << std::endl;
            } 
        }
    }
    windPerDest.find(dAddr)->second = newWind;
}