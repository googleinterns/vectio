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

#ifndef __INET_LISTENINGDECISION_H
#define __INET_LISTENINGDECISION_H

#include "inet/physicallayer/contract/IListeningDecision.h"

namespace inet {

namespace physicallayer {

class INET_API ListeningDecision : public IListeningDecision, public cObject
{
  protected:
    const IListening *listening;
    const bool isListeningPossible_;

  public:
    ListeningDecision(const IListening *listening, bool isListeningPossible_);

    virtual void printToStream(std::ostream& stream) const;

    virtual const IListening *getListening() const { return listening; }

    virtual bool isListeningPossible() const { return isListeningPossible_; }
};

} // namespace physicallayer

} // namespace inet

#endif // ifndef __INET_LISTENINGDECISION_H

