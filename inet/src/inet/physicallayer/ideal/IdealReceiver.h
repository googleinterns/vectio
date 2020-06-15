//
// Copyright (C) 2013 OpenSim Ltd.
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

#ifndef __INET_IDEALRECEIVER_H
#define __INET_IDEALRECEIVER_H

#include "inet/physicallayer/base/ReceiverBase.h"

namespace inet {

namespace physicallayer {

class INET_API IdealReceiver : public ReceiverBase
{
  protected:
    bool ignoreInterference;

  protected:
    virtual void initialize(int stage);
    virtual bool computeIsReceptionPossible(const IListening *listening, const IReception *reception) const;
    virtual bool computeIsReceptionAttempted(const IListening *listening, const IReception *reception, const IInterference *interference) const;

  public:
    IdealReceiver();

    virtual void printToStream(std::ostream& stream) const;
    virtual const IListening *createListening(const IRadio *radio, const simtime_t startTime, const simtime_t endTime, const Coord startPosition, const Coord endPosition) const;
    virtual const IListeningDecision *computeListeningDecision(const IListening *listening, const IInterference *interference) const;
    virtual const IReceptionDecision *computeReceptionDecision(const IListening *listening, const IReception *reception, const IInterference *interference) const;
};

} // namespace physicallayer

} // namespace inet

#endif // ifndef __INET_IDEALRECEIVER_H

