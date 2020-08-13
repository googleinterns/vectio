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

package homatransport.common;

import inet.node.inet.NodeBase;
import inet.applications.ITCPApp;
import inet.applications.IUDPApp;
import inet.transportlayer.ITCP;
import inet.transportlayer.IUDP;
import homatransport.application.ITrafficGeneratorApp;
import homatransport.transport.ITransportScheme;

//
// The nic module contains the offloaded transport functionalities. It is 
// directly connected to PCIE, which transfers the messages to the nic module 
// from the appmaster module. The transport inside this module is assumed to be
// connected to an INET udp socket, which helps transfer the messages to 
// dsired destination nic module in the topology
//

module NicBase extends NodeBase
{
    parameters:
        @display("i=device/pc2");
        xml hostConfig;
        int nicLinkSpeed @unit(Gbps);
        int fabricLinkSpeed @unit(Gbps);
        int numTrafficGeneratorApp;

        bool hasTransportScheme = default(numTrafficGeneratorApp>0);
        bool hasUdp = default(numTrafficGeneratorApp>0);

        string udpType = default(firstAvailable("UDP","UDP_None"));
        string transportSchemeType =
                default(firstAvailable("HomaTransport", "TransportSchemeNone"));
        forwarding = default(false);  // disable routing by default
        networkLayer.proxyARP = default(false);

        double edgeLinkDelay @unit(us);
        double fabricLinkDelay @unit(us);
        double hostSwTurnAroundTime @unit(us);
        double hostNicSxThinkTime @unit(us);
        double switchFixDelay @unit(us);

        bool isFabricCutThrough;
        bool isSingleSpeedFabric;

        int degOverComm;
        string logFile;
        string switchLogFile;
        string transportSchedulingPolicy;
        bool congCtrl;
        double ai;
        double md;
    gates:
        input pcieIn;
        output pcieOut;

    submodules:
        transportScheme: <transportSchemeType> like ITransportScheme if hasTransportScheme {
            parameters:
                @display("p=445,112");
                transportConfig = xmldoc("config.xml", "/topologyConfig/hostConfig[@id=$PARENTMODULE_INDEX]/transportConfig");
                nicLinkSpeed = nicLinkSpeed;
                fabricLinkSpeed = fabricLinkSpeed;
                edgeLinkDelay = edgeLinkDelay;
                fabricLinkDelay = fabricLinkDelay;
                hostSwTurnAroundTime = hostSwTurnAroundTime;
                hostNicSxThinkTime = hostNicSxThinkTime;
                switchFixDelay = switchFixDelay;
                isFabricCutThrough = isFabricCutThrough;
                isSingleSpeedFabric = isSingleSpeedFabric;
                degOverComm = degOverComm;
                logFile = logFile;
                switchLogFile = switchLogFile;
                transportSchedulingPolicy = transportSchedulingPolicy;
                congCtrl = congCtrl;
                ai = ai;
                md = md;
        }

        udp: <udpType> like IUDP if hasUdp {
            parameters:
                @display("p=394,176");
        }

    connections allowunconnected:
        pcieIn --> transportScheme.appIn++;
        pcieOut <-- transportScheme.appOut++;

        transportScheme.udpOut --> udp.appIn++ if hasTransportScheme;
        transportScheme.udpIn <-- udp.appOut++ if hasTransportScheme;

        udp.ipOut --> networkLayer.transportIn++ if hasUdp;
        udp.ipIn <-- networkLayer.transportOut++ if hasUdp;
}

