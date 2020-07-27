//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General public License for more details.
//
// You should have received a copy of the GNU Lesser General public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
//

#ifndef __HOMATRANSPORT_VECTIOTRANSPORT_H_
#define __HOMATRANSPORT_VECTIOTRANSPORT_H_

#include <omnetpp.h>
#include <unordered_map>
#include <list>
#include <queue>
#include "common/Minimal.h"
#include "inet/transportlayer/contract/udp/UDPSocket.h"
#include "application/AppMessage_m.h"
#include "transport/HomaPkt.h"

/**
 * An near optimal priority based transport scheme for minimizing the average
 * completion time of messages. For every packet of a message, it sets the
 * message size field and a priority field equal to the remaining bytes of the
 * message not yet send. This transport will only be near optimal if the network
 * has priority queues and only for many-senders/single-receiver scenario. The
 * scheduling mechanism for the priority queues in the network would always
 * choose the lowest priority packet that belongs to shortes message among all
 * packets in the queue.
 */
class TimerContext
        {
            public:
              inet::L3Address srcAddr;
              inet::L3Address destAddr;
              uint64_t msgIdAtSender;
              int missedPktSeqNo;
        };

class VectioTransport : public cSimpleModule
{
  public:

  public:
    VectioTransport();
    ~VectioTransport();

  protected:
    virtual void initialize();
    virtual void handleMessage(cMessage *msg);
    virtual void processStart();
    virtual void processStop();
    virtual void processMsgFromApp(AppMessage* sendMsg);
    virtual void processRcvdPkt(HomaPkt* rxPkt);
    virtual void processReqPkt(HomaPkt* rxPkt);
    virtual void processDataPkt(HomaPkt* rxPkt);
    virtual void processAckPkt(HomaPkt* rxPkt);
    virtual void processNackPkt(HomaPkt* rxPkt);
    virtual void processPendingMsgsToGrant();
    virtual void processPendingMsgsToSend();
    virtual void processRetxTimer(TimerContext* timerContext);
    virtual void processSendQueue();
    virtual void finish();

    virtual HomaPkt* extractGrantPkt(const char* schedulingPolicy);
    virtual HomaPkt* extractDataPkt(const char* schedulingPolicy);

    virtual double calculateTargetDelay(inet::L3Address srcAddr, inet::L3Address destAddr);
    virtual void adjustWindSize(inet::L3Address srcAddr, int pktSize);

    /**
     * A self message essentially models a timer object for this transport and
     * can have one of the following types.
     */
    enum SelfMsgKind
    {
        START = 1,  // Timer type when the transport is in initialization phase.
        STOP  = 2,   // Timer type when the transport is in cleaning phase.
        INBOUNDQUEUE = 3, // Timer type when the transport wants to process the 
                       // grant queue
        OUTBOUNDQUEUE = 4, // Timer type when the transport wants to process the 
                       // grant queue
        RETXTIMER = 5,
        SENDQUEUE = 6
    };

    class InboundMsg
    {
      protected:
        //set of received packets
        std::set<int> rxPkts;
        // map of missed pkts -- pktSeqNo -- to the time detected missing
        std::map<int,simtime_t> missedPkts;

      public:
        explicit InboundMsg();
        explicit InboundMsg(HomaPkt* rxPkt, VectioTransport* transport);
        ~InboundMsg();
        bool appendPktData(HomaPkt* rxPkt);
        void checkAndSendNack();
        bool updateRxAndMissedPkts(int pktSeqNo);

      public:
        int numBytesToRecv;
        uint32_t msgByteLen;
        uint32_t totalBytesOnWire;
        inet::L3Address srcAddr;
        inet::L3Address destAddr;
        uint64_t msgIdAtSender;
        simtime_t msgCreationTime;
        double retxTimeout = 10000000.0e-6;
        // int grantSizeBytes = 1000; //TODO -- get this value from the parent class automatically
        int largestPktSeqRcvd = -1;
        int largestByteRcvd = -1;
        VectioTransport* transport;
        int bytesGranted = -1;
        int bytesInFlight = -1;
        // simtime_t firstPktSentTime;
        simtime_t firstPktSchedTime;
        simtime_t firstPktEnqueueTime;
    };

    class OutboundMsg
    {
      public:
        explicit OutboundMsg();
        explicit OutboundMsg(HomaPkt* sxPkt);
        ~OutboundMsg();
        bool rmvAckedPktData(HomaPkt* ack);

      public:
        int numBytesToSend;
        uint32_t nextByteToSend;
        uint32_t msgByteLen;
        uint32_t totalBytesOnWire;
        inet::L3Address srcAddr;
        inet::L3Address destAddr;
        uint64_t msgIdAtSender;
        simtime_t msgCreationTime;
        // int grantSizeBytes = 1000; //TODO -- get this value from the parent class automatically
        uint16_t schedPrio;
    };

  protected:
    //src interface address
    inet::L3Address srcAddress;

    // UDP socket through which this transport send and receive packets.
    inet::UDPSocket socket;

    // Timer object for this transport. Will be used for implementing timely
    // scheduled
    cMessage* selfMsg;
    cMessage* inboundGrantQueueTimer;
    cMessage* outboundGrantQueueTimer;
    cMessage* sendQueueTimer;
    cMessage* retxTimer;

    // udp ports through which this transport send and receive packets
    int localPort;
    int destPort;

    bool logEvents;
    bool logPacketEvents;

    // variables and states kept for administering outbound messages
    uint32_t maxDataBytesInPkt;

    // State and variables kept for managing inbound messages
    // Defines a map to keep a all partially received inbound messages. The key
    // is the msgId at the sender and value is a list of pointer to rx
    // messages currently under transmission from different senders that
    // happened to have same id at the sender side.
    typedef std::unordered_map<uint64_t, std::list<InboundMsg*>>
            IncompleteRxMsgsMap;
    IncompleteRxMsgsMap incompleteRxMsgsMap;

    // State and variables kept for managing outbound messages
    // Defines a map to keep a all partially fulfilled outbound messages. 
    // The key is msgId at the sender and value is the corresponding outboundmsg 
    typedef std::map<uint64_t, OutboundMsg*>
            IncompleteSxMsgsMap;
    IncompleteSxMsgsMap incompleteSxMsgsMap;

    //inboundGrantQueue used at the sender to pace & schedule transmit data pkts
    std::queue<HomaPkt*> inboundGrantQueue;

    //outboundGrantQueue used at the receiver to pace & schedule grant pkts 
    std::queue<HomaPkt*> outboundGrantQueue;
    bool inboundGrantQueueBusy;
    bool outboundGrantQueueBusy;
    int freeGrantSize = 10000;
    double nicBandwidth = 10e9; //TODO initialize using ini file

    //use this instead of outbound grant queue
    //whenever you're ready to send any grant, find the message to send the 
    //grant to using the desired scheduling criteria
    typedef std::map<uint64_t, std::set<std::pair<inet::L3Address,int>>> PendingMsgsToGrant;
    PendingMsgsToGrant pendingMsgsToGrant;

    typedef std::map<uint64_t, int> PendingMsgsToSend;
    PendingMsgsToSend pendingMsgsToSend;

    typedef std::map<uint64_t, std::set<inet::L3Address>> FinishedMsgsMap;
    FinishedMsgsMap finishedMsgs;

    double currentRtt = 2.5 * 2.0 * 1.6e-6;

    // max allowed inflight grant bytes per receiver
    int allowedInFlightGrantedBytes = ((int)(2.5 * 2.0 * 1.6e-6 * 10e9 / 8.0));
    int allowedInFlightGrantedBytesIntraPod = ((int)(2.5 * 2.0 * 1.6e-6 * 10e9 / 8.0));

    double baseRtt = 2.5 * 2.0 * 1.6e-6;
    double baseRttIntraPod = 1.5 * 2.0 * 1.6e-6;

    int currentRcvInFlightGrantBytes = 0;

    typedef std::map<inet::L3Address,int> SenderInFlightGrantBytes;
    SenderInFlightGrantBytes senderInFlightGrantBytes;

    // for each sender, stores a pair of current actively granted msg and
    // bytes remaining to grant
    typedef std::map<inet::L3Address,std::pair<uint64_t,int>> SenderActiveGrantedMsg;
    SenderActiveGrantedMsg senderActiveGrantedMsg;

    int degOverComm = 4; 

    std::queue<HomaPkt*> sendQueue;
    bool sendQueueBusy;
    int totalSendQueueSizeInBytes;
    simtime_t sendQueueFreeTime;
    double INFINITISIMALTIME = 1e-9;

    int extraGrantedBytes = 0;
    typedef std::map<inet::L3Address,simtime_t> LastHeardFromSender;
    LastHeardFromSender lastHeardFromSender;

    typedef std::map<inet::L3Address,simtime_t> LastGrantSentToSender;
    LastGrantSentToSender lastGrantSentToSender;

    typedef std::map<inet::L3Address,std::set<uint64_t>> GrantedMsgsPerSender;
    GrantedMsgsPerSender grantedMsgsPerSender;

    double lastHeardThreshold = 3.0 * 2.5 * 2.0 * 1.6e-6;//3RTT for now

    double ai = 1.0;
    double md = 0.25;
    int maxWindSize;
    int minWindSize;
    typedef std::map<inet::L3Address, double> RttPerSender;
    RttPerSender currRttPerSender;
    RttPerSender targetDelayPerSender;
    typedef std::map<inet::L3Address, int> WindPerSender;
    WindPerSender windPerSender;
    typedef std::map<inet::L3Address, simtime_t> LastReducedWind;
    LastReducedWind lastReducedWind;
    double queueingDelayFactor = 2.0;

    double edgeLinkDelay;
    double fabricLinkDelay;
    double hostSwTurnAroundTime;
    double hostNicSxThinkTime;
    double switchFixDelay;
    double nicLinkSpeed;
    double fabricLinkSpeed;
    bool isFabricCutThrough;
    bool isSingleSpeedFabric;


    public:
      int grantSizeBytes = 1000;
};

#endif
