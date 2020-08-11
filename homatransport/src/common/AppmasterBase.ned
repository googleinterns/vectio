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
// This module contains the app submodules, which include traffic generator
// which generates messages based on the input workload distribution
// and the appmaster module sends these messages to the nic module via PCIE
//

module AppmasterBase
{
    parameters:
        @display("i=device/pc2");
        xml hostConfig;
        int nicLinkSpeed @unit(Gbps);
        int fabricLinkSpeed @unit(Gbps);

        int numTrafficGeneratorApp = default(0);
        // no of TCP apps. Specify the app types in INI file with
        // tcpApp[0..1].typename="TCPEchoApp" syntax
        int numTcpApps = default(0);

        // no of UDP apps. Specify the app types in INI file with
        // udpApp[0..1].typename="UDPVideoStreamCli" syntax
        int numUdpApps = default(0);

        double edgeLinkDelay @unit(us);
        double fabricLinkDelay @unit(us);
        double hostSwTurnAroundTime @unit(us);
        double hostNicSxThinkTime @unit(us);
        double switchFixDelay @unit(us);

        string outputFileName;
        string workloadFileName;
    gates:
        input pcieIn;
        output pcieOut;

    submodules:
        trafficGeneratorApp[numTrafficGeneratorApp]: <default("WorkloadSynthesizer")> like ITrafficGeneratorApp {
            parameters:
                @display("p=490,38");
                appConfig = xmldoc("config.xml", "/topologyConfig/hostConfig[@id=$PARENTMODULE_INDEX]/appConfig");
                nicLinkSpeed = nicLinkSpeed;
                fabricLinkSpeed = fabricLinkSpeed;
                edgeLinkDelay = edgeLinkDelay;
                fabricLinkDelay = fabricLinkDelay;

                hostSwTurnAroundTime = hostSwTurnAroundTime;
                hostNicSxThinkTime = hostNicSxThinkTime;
                switchFixDelay = switchFixDelay;

                outputFileName = outputFileName;
                workloadFileName = workloadFileName;
        }

        udpApp[numUdpApps]: <> like IUDPApp {
            parameters:
                @display("p=308,110,row,60");
        }

        tcpApp[numTcpApps]: <> like ITCPApp {
            parameters:
                @display("p=147,54,row,60");
        }

    connections allowunconnected:
        for i=0..numTrafficGeneratorApp-1 {
            trafficGeneratorApp[i].transportOut --> pcieOut;
            trafficGeneratorApp[i].transportIn <-- pcieIn;
        }

        for i=0..numUdpApps-1 {
            udpApp[i].udpOut --> pcieOut;
            udpApp[i].udpIn <-- pcieIn;
        }

        for i=0..numTcpApps-1 {
            tcpApp[i].tcpOut --> pcieOut;
            tcpApp[i].tcpIn <-- pcieIn;
        }
}

