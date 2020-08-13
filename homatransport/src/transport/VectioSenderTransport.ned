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

package homatransport.transport;
import homatransport.transport.ITransportScheme;

//
// Defines the vectio sender transport
//
simple VectioSenderTransport like ITransportScheme
{
    parameters:
        string interfaceTableModule;
        xml transportConfig = default(xml("<param/>"));
        int localPort = default(-1);
        int destPort;
        int nicLinkSpeed @unit(Gbps) = default(10Gbps);
        int fabricLinkSpeed @unit(Gbps) = default(10Gbps);
        string logFile = default("output.log");
        string switchLogFile = default("switch.log");
        bool logEvents = default(false);

        double edgeLinkDelay @unit(us);
        double fabricLinkDelay @unit(us);
        double hostSwTurnAroundTime @unit(us);
        double hostNicSxThinkTime @unit(us);
        double switchFixDelay @unit(us);

        bool isFabricCutThrough;
        bool isSingleSpeedFabric;

        int degOverComm = default(8);
        string transportSchedulingPolicy = default("SRPT");

        bool congCtrl;
        double ai;
        double md;

    gates:
        input appIn[] @labels(AppMessage/down);
        input udpIn @labels(UDPControlInfo/up);
        output appOut[] @labels(AppMessage/up);
        output udpOut @labels(UDPControlInfo/down);
}
