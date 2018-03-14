using System;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.Transport;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using PcapDotNet.Packets;
using System.Collections.Generic;
using PcapDotNet.Packets.Icmp;
using System.Diagnostics;

namespace SteganoNetLib
{
    public static class NetStandard
    {
        //class is separated by ISO-OSI RM model layers

        //---------L2------------------------------------------------------------------------------------------------------------

        public static EthernetLayer GetEthernetLayer(MacAddress MacAddressSource, MacAddress MacAddressDestination)
        {
            EthernetLayer ethernetVrstva = new EthernetLayer
            {
                Source = MacAddressSource,
                Destination = MacAddressDestination,
                EtherType = EthernetType.None //Will be filled automatically.
            };
            return ethernetVrstva;
        }
        public static MacAddress GetMacAddressFromArp(IpV4Address ipAddressInterface) //when mac address is not known locally
        {
            //name GetMacAddress should be rather expected in NetDevice class

            if (ipAddressInterface == null || ipAddressInterface.ToString().Length == 0 || ipAddressInterface.ToString().Equals("0.0.0.0")) //in case of input problem or unknown
            {
                ipAddressInterface = new IpV4Address(GetDefaultGateway().ToString()); //get alternative default gateway ip                
            }

            try //source: https://stephenhaunts.com/2014/01/06/getting-the-mac-address-for-a-machine-on-the-network/
            {
                byte[] macAddr = new byte[6];
                uint macAddrLen = (uint)macAddr.Length;
                string[] str = new string[(int)macAddrLen]; //bit too classic C but working...

                if (SendARP(StringIPToInt(ipAddressInterface.ToString()), 0, macAddr, ref macAddrLen) != 0)
                {
                    //if requested MAC is not found, ask for MAC address of system default gateway
                    if (SendARP(StringIPToInt(GetDefaultGateway().ToString()), 0, macAddr, ref macAddrLen) != 0)
                    {
                        //if still not valid then return smth universal
                        return NetDevice.GetRandomMacAddress();
                    }
                }
                for (int i = 0; i < macAddrLen; i++)
                {
                    str[i] = macAddr[i].ToString("x2");
                }

                return new MacAddress(string.Join(":", str).ToUpper()); //get L2 destination address for inserted IP address                
            }
            catch
            {
                return NetDevice.GetRandomMacAddress();
            }
        }

        [DllImport("iphlpapi.dll", ExactSpelling = true)] //used by SendARP() + GetMacAddress()
        private static extern int SendARP(int DestIP, int SrcIP, byte[] pMacAddr, ref uint PhyAddrLen); //used by GetMacAddress

        //---------L3------------------------------------------------------------------------------------------------------------
        public static IpV4Layer GetIpV4Layer(IpV4Address SourceIP, IpV4Address DestinationIP)
        {
            IpV4Layer ipv4Vrstva = new IpV4Layer();
            ipv4Vrstva.TypeOfService = Convert.ToByte(0); //STEGO ready //0 default value
            ipv4Vrstva.Source = SourceIP;
            ipv4Vrstva.CurrentDestination = DestinationIP; //ipv4Vrstva.Destination is read only
            ipv4Vrstva.Fragmentation = IpV4Fragmentation.None; //new IpV4Fragmentation(IpV4FragmentationOptions.DoNotFragment, 0),
            ipv4Vrstva.HeaderChecksum = null; //Will be filled automatically.
            ipv4Vrstva.Identification = 1;
            ipv4Vrstva.Options = IpV4Options.None;
            ipv4Vrstva.Ttl = 128;
            /*
            if (carryingLayer == IpV4Protocol.Tcp)
                ipv4Vrstva.Protocol = IpV4Protocol.Tcp;

            if (carryingLayer == IpV4Protocol.Udp)
                ipv4Vrstva.Protocol = IpV4Protocol.Udp;
            */
            return ipv4Vrstva;
        }

        public static IpV4Address GetDefaultGateway() //returns default gateway from system, not from PcapDotNet
        {
            //source: http://stackoverflow.com/questions/13634868/get-the-default-gateway

            IPAddress result = null;
            var cards = NetworkInterface.GetAllNetworkInterfaces().ToList();
            if (cards.Any())
            {
                foreach (var card in cards)
                {
                    var props = card.GetIPProperties();
                    if (props == null)
                        continue;

                    var gateways = props.GatewayAddresses;
                    if (!gateways.Any())
                        continue;

                    var gateway = gateways.FirstOrDefault(g => g.Address.AddressFamily.ToString() == "InterNetwork");
                    if (gateway == null)
                        continue;

                    result = gateway.Address;
                    break;
                };
            }

            string address = result.ToString();
            IpV4Address ipv4address = new IpV4Address(address);
            return ipv4address;
        }

        public static List<Layer> GetIcmpEchoReplyPacket(MacAddress MacAddressLocal, MacAddress MacAddressRemote, IpV4Address SourceIP, IpV4Address DestinationIP, IcmpEchoDatagram icmp)
        {
            //create legacy "datagram" which is going to be sent back
            List<Layer> layers = new List<Layer>(); //list of used layers
            layers.Add(GetEthernetLayer(MacAddressLocal, MacAddressRemote)); //L2
            layers.Add(GetIpV4Layer(SourceIP, DestinationIP));
            IcmpEchoReplyLayer icmpLayer = new IcmpEchoReplyLayer();
            icmpLayer.SequenceNumber = icmp.SequenceNumber; //field MUST be returned to the sender unaltered
            icmpLayer.Identifier = icmp.Identifier; //field MUST be returned to the sender unaltered
            layers.Add(icmpLayer);
            return (layers);
        }


        //checks for used ports and retrieves the first free port <returns>the free port or 0 if it did not find a free port</returns>
        public static ushort GetAvailablePort(ushort startingPort)
        {
            //source: https://gist.github.com/jrusbatch/4211535

            IPEndPoint[] endPoints;
            List<int> portArray = new List<int>();

            IPGlobalProperties properties = IPGlobalProperties.GetIPGlobalProperties();

            //getting active connections
            TcpConnectionInformation[] connections = properties.GetActiveTcpConnections();
            portArray.AddRange(from n in connections where n.LocalEndPoint.Port >= startingPort select n.LocalEndPoint.Port);

            //getting active tcp listners - WCF service listening in tcp
            endPoints = properties.GetActiveTcpListeners();
            portArray.AddRange(from n in endPoints where n.Port >= startingPort select n.Port);

            //getting active udp listeners
            endPoints = properties.GetActiveUdpListeners();
            portArray.AddRange(from n in endPoints where n.Port >= startingPort select n.Port);

            portArray.Sort();

            for (ushort i = startingPort; i < UInt16.MaxValue; i++)
                if (!portArray.Contains(i))
                    return i;

            return 0;
        }

        public static int StringIPToInt(string IPString)
        {
            //source https://www.codeproject.com/Messages/1194102/iphlpapi-dll-and-sendarp.aspx

            string[] _splitString = IPString.Split(new char[] { '.' });
            int IpAddInInt = 0;
            if (_splitString.Length < 4)
            {
                throw new ArgumentException("Please pass in a valid IP in dotted-quad notation!", "IPString");
            }
            else
            {
                IpAddInInt += (int)(int.Parse(_splitString[3]) * Math.Pow(256, 0));
                IpAddInInt += (int)(int.Parse(_splitString[2]) * Math.Pow(256, 1));
                IpAddInInt += (int)(int.Parse(_splitString[1]) * Math.Pow(256, 2));
                IpAddInInt += (int)(int.Parse(_splitString[0]) * Math.Pow(256, 3));
            }

            IpAddInInt = (int)(((IpAddInInt & 0x000000ff) << 24) + ((IpAddInInt & 0x0000ff00) << 8) + ((IpAddInInt & 0x00ff0000) >> 8) + ((IpAddInInt & 0xff000000) >> 24));
            return IpAddInInt;
        }

        //---------L4------------------------------------------------------------------------------------------------------------

        public static UdpLayer GetUdpLayer(ushort sourcePort, ushort destinationPort)
        {
            UdpLayer udpLayer = new UdpLayer();
            udpLayer.SourcePort = sourcePort;
            udpLayer.DestinationPort = destinationPort;
            udpLayer.Checksum = null; // Will be filled automatically
            udpLayer.CalculateChecksumValue = true;

            return udpLayer;
        }

        public static TcpLayer GetTcpLayer(ushort sourcePort, ushort destinationPort, uint sequenceNumber, uint acknowledgmentNumber, TcpControlBits SetBit = TcpControlBits.Synchronize)
        {
           /* How it works
            * client sending SYN               seq = generated         ack = 0
            * server sending SYNACK            seq = generated         ack = received seq + 1
            * client sending ACK               seq = received ack      ack = received seq + 1
            *
            * client sending PSH, DATA         seq = same as before    ack = same as before
            * server sending ACK               seq = received ack      ack = received seq + size of data
            * server sending DATA optional     seq = same as before    ack = same as before
            * client sending ACK               seq = received ack      ack = received seq + size of data
            * client sending DATA              seq = same as before    ack = same as before
            * server sending ACK               seq = received ack      ack = received seq + size of data
            * client sending DATA              seq = same as before    ack = same as before
            * ...
            * server sending ACK               seq = received ack      ack = received seq + size of data
            * client sending FINACK            seq = same as before    ack = same as before
            * server sending FINACK            seq = received ack      ack = received seq + 1
            * client sending ACK               seq = received ack      ack = received seq + 1 
            */

            TcpLayer tcpLayer = new TcpLayer
            {
                SourcePort = sourcePort,
                DestinationPort = destinationPort,
                SequenceNumber = sequenceNumber,
                AcknowledgmentNumber = acknowledgmentNumber,
                ControlBits = SetBit, //needs to be changed regarding flow of TCP!

                Window = 100,
                Checksum = null, //Will be filled automatically
                UrgentPointer = 0,
                Options = TcpOptions.None
            };
            return tcpLayer;
        }

        public static uint? WaitForTcpAck(PcapDotNet.Core.PacketCommunicator communicator, IpV4Address SourceIpV4, IpV4Address DestinationIpV4, ushort _sourcePort, ushort _destinationPort, uint ackNumberExpected, TcpControlBits waitForBit = TcpControlBits.Acknowledgment)
        {
            communicator.SetFilter("tcp and src " + DestinationIpV4 + " and dst " + SourceIpV4 + " and src port " + _destinationPort + " and dst port " + _sourcePort);
            Stopwatch sw = new Stopwatch(); //for timeout
            sw.Start();

            while (true)
            {
                if (communicator.ReceivePacket(out Packet packet) == PcapDotNet.Core.PacketCommunicatorReceiveResult.Ok && packet.Ethernet.IpV4.Tcp.ControlBits == waitForBit)
                {
                    if (packet.Ethernet.IpV4.Tcp.AcknowledgmentNumber == ackNumberExpected) //debug point
                    {
                        return packet.Ethernet.IpV4.Tcp.SequenceNumber; //if ACK fits, return SEQ
                    }
                }

                if (sw.ElapsedMilliseconds > 20000) //timeout break
                {
                    sw.Stop();
                    return null;
                }
            }
        }

    }
}
