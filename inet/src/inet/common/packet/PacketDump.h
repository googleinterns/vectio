//
// Copyright (C) 2005 Michael Tuexen
// Copyright (C) 2008 Irene Ruengeler
// Copyright (C) 2009 Thomas Dreibholz
// Copyright (C) 2011 Zoltan Bojthe
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program; if not, see <http://www.gnu.org/licenses/>.
//

#ifndef __INET_PACKETDUMP_H
#define __INET_PACKETDUMP_H

#include "inet/common/INETDefs.h"

namespace inet {

// Foreign declarations:
class IPv4Datagram;
class IPv6Datagram;
namespace tcp { class TCPSegment; }
class UDPPacket;
class ARPPacket;
namespace sctp { class SCTPMessage; }

/**
 * Utility class that provides tcpdump-like functionality. It prints
 * information about each packet on the given output stream.
 */
class INET_API PacketDump
{
  protected:
    bool verbose;
    std::ostream *outp;

  public:
    /**
     * Constructor. The output stream initially points to the C++ standard
     * output (std::cout); you probably want to call
     * <code>setOutStream(ev.getOStream())</code> to redirect it to EV.
     */
    PacketDump();

    /**
     * Destructor. It does not close the output stream.
     */
    ~PacketDump();

    /**
     * Sets the output stream.
     */
    void setOutStream(std::ostream& o) { outp = &o; }

    /**
     * Returns the output stream.
     */
    std::ostream& getOutStream() const { return *outp; }

    /**
     * Enable/disable verbose output.
     */
    void setVerbose(bool verb) { verbose = verb; }

    /**
     * Returns the verbosity flag.
     */
    bool isVerbose() const { return verbose; }

    /**
     * Writes the given text on the output stream.
     */
    void dump(const char *label, const char *msg);

    /**
     * Dumps info about the given packet. It dispatches to the more specific
     * dump functions. The l2r parameter denotes the direction of the packet.
     */
    void dumpPacket(bool l2r, cPacket *packet);

    /**
     * Dumps info about the given IPv4 datagram. The l2r parameter denotes the
     * direction of the packet.
     */
    void dumpIPv4(bool l2r, const char *label, IPv4Datagram *dgram, const char *comment = NULL);

    void dumpARP(bool l2r, const char *label, ARPPacket *dgram, const char *comment = NULL);

    /**
     * Dumps info about the given IPv6 datagram. The l2r parameter denotes
     * the direction of the packet.
     */
    void dumpIPv6(bool l2r, const char *label, IPv6Datagram *dgram, const char *comment = NULL);

    /**
     * Dumps info about the given SCTP message.
     */
    void sctpDump(const char *label, sctp::SCTPMessage *sctpmsg, const std::string& srcAddr,
            const std::string& destAddr, const char *comment = NULL);

    /**
     * Dumps info about the given TCP segment.
     */
    void tcpDump(bool l2r, const char *label, tcp::TCPSegment *tcpseg, const std::string& srcAddr,
            const std::string& destAddr, const char *comment = NULL);

    /**
     * Dumps info about the given UDP packet.
     */
    void udpDump(bool l2r, const char *label, UDPPacket *udppkt, const std::string& srcAddr,
            const std::string& destAddr, const char *comment);
};

} // namespace inet

#endif // ifndef __INET_PACKETDUMP_H

