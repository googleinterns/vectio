//
// Copyright (C) 2006 Levente Meszaros
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program; if not, see <http://www.gnu.org/licenses/>.
//

#ifndef __INET_ETHERMACFULLDUPLEX_H
#define __INET_ETHERMACFULLDUPLEX_H

#include "inet/common/INETDefs.h"

#include "inet/linklayer/ethernet/EtherMACBase.h"

namespace inet {

/**
 * A simplified version of EtherMAC. Since modern Ethernets typically
 * operate over duplex links where's no contention, the original CSMA/CD
 * algorithm is no longer needed. This simplified implementation doesn't
 * contain CSMA/CD, frames are just simply queued up and sent out one by one.
 */
class INET_API EtherMACFullDuplex : public EtherMACBase
{
  public:
    EtherMACFullDuplex();

  protected:
    virtual int numInitStages() const { return NUM_INIT_STAGES; }
    virtual void initialize(int stage);
    virtual void initializeStatistics();
    virtual void initializeFlags();
    virtual void handleMessage(cMessage *msg);

    // finish
    virtual void finish();

    // event handlers
    virtual void handleEndIFGPeriod();
    virtual void handleEndTxPeriod();
    virtual void handleEndPausePeriod();
    virtual void handleSelfMessage(cMessage *msg);

    // helpers
    virtual void startFrameTransmission();
    virtual void processFrameFromUpperLayer(EtherFrame *frame);
    virtual void processMsgFromNetwork(EtherTraffic *msg);
    virtual void processReceivedDataFrame(EtherFrame *frame);
    virtual void processPauseCommand(int pauseUnits);
    virtual void scheduleEndIFGPeriod();
    virtual void scheduleEndPausePeriod(int pauseUnits);
    virtual void beginSendFrames();

    // statistics
    simtime_t totalSuccessfulRxTime;    // total duration of successful transmissions on channel
    simtime_t totalSuccessfulTxTime;

  protected:
    // if a homaPkt is being sent or received, this function counts number of
    // bytes in that packet.
    virtual void countHomaPktBytes(EtherFrame* curFrame, bool isSent);

};

} // namespace inet

#endif // ifndef __INET_ETHERMACFULLDUPLEX_H

