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
using PcapDotNet.Packets.Dns;
using PcapDotNet.Base;
using System.Text;
using PcapDotNet.Packets.Http;

namespace SteganoNetLib
{
    public static class NetStandard
    {
        //class is separated by ISO-OSI RM model layers

        //timers public copy to DelayInMs when used and then executed
        public const int TcpTimeoutInMs = 20000; //gap between all packets in miliseconds
        public const int DnsTimeoutInMs = NetSenderClient.delayDns * 2; //how long to wait for official DNS answer

        //public static List<String> TCPphrases = new List<string> { "SYN", "SYN ACK", "ACK SYNACK", "DATA", "DATA ACK", "FIN", "FIN ACK", "ACK FINACK" }; //TCP legal
        private static Random rand = new Random(); //TCP legal values                

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

            try
            {
                var mac = NetDevice.GetLocalMacAddress(ipAddressInterface); //first ask local device for mac based on IP
                if (mac != null)
                {
                    return new MacAddress(mac.ToString());
                }
                else
                {
                    throw new Exception(); //is not local IP
                }
            }
            catch //or ask via ARP (L2)
            {
                try //source: https://stephenhaunts.com/2014/01/06/getting-the-mac-address-for-a-machine-on-the-network/
                {
                    byte[] macAddr = new byte[6];
                    uint macAddrLen = (uint)macAddr.Length;
                    string[] str = new string[(int)macAddrLen]; //a bit too classic C but working...

                    if (SendARP(StringIPToInt(ipAddressInterface.ToString()), 0, macAddr, ref macAddrLen) != 0)
                    {
                        //if requested MAC is not found, ask for MAC address of system default gateway
                        if (SendARP(StringIPToInt(GetDefaultGateway().ToString()), 0, macAddr, ref macAddrLen) != 0)
                        {
                            //if still not valid then return smth universal
                            //return NetDevice.GetRandomMacAddress(); //problem on 802.11 alias WiFi
                            throw new Exception(); //use backup solution
                        }
                    }
                    for (int i = 0; i < macAddrLen; i++)
                    {
                        str[i] = macAddr[i].ToString("x2");
                    }

                    return new MacAddress(string.Join(":", str).ToUpper()); //get L2 destination address for inserted IP address    
                }
                catch //everything fails
                {
                    try
                    {
                        //ask for MAC address of local gateway
                        return GetMacAddressFromArp(new IpV4Address(GetDefaultGateway().ToString()));
                    }
                    catch
                    {
                        //no idea, just something valid
                        return NetDevice.GetRandomMacAddress(); //problem on 802.11 alias WiFi
                    }
                }
            }
        }

        [DllImport("iphlpapi.dll", ExactSpelling = true)] //used by SendARP() + GetMacAddress()
        private static extern int SendARP(int DestIP, int SrcIP, byte[] pMacAddr, ref uint PhyAddrLen); //used by GetMacAddress

        //---------L3------------------------------------------------------------------------------------------------------------
        public static IpV4Layer GetIpV4Layer(IpV4Address SourceIP, IpV4Address DestinationIP)
        {
            IpV4Layer ipv4Vrstva = new IpV4Layer
            {
                TypeOfService = Convert.ToByte(0),
                Source = SourceIP,
                CurrentDestination = DestinationIP, //ipv4Vrstva.Destination is read only
                Fragmentation = IpV4Fragmentation.None, //new IpV4Fragmentation(IpV4FragmentationOptions.DoNotFragment, 0),
                HeaderChecksum = null, //Will be filled automatically.
                Identification = 1,
                Options = IpV4Options.None,
                Ttl = 128
            };
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
            if (icmp == null) { return null; } //extra protection

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


        //checks for used ports and retrieves the first free port <returns>the free port or 0 if it did not find a free port
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

        public static TcpLayer GetTcpLayer(ushort sourcePort, ushort destinationPort, uint sequenceNumber = 65535, uint acknowledgmentNumber = 65535, TcpControlBits SetBit = TcpControlBits.Synchronize)
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

            uint seqNumberLocal = (sequenceNumber == 65535) ? GetSynOrAckRandNumber() : sequenceNumber;
            uint ackNumberLocal = (acknowledgmentNumber == 65535) ? GetSynOrAckRandNumber() : acknowledgmentNumber;

            TcpLayer tcpLayer = new TcpLayer
            {
                SourcePort = sourcePort,
                DestinationPort = destinationPort,
                SequenceNumber = seqNumberLocal,
                AcknowledgmentNumber = ackNumberLocal,
                ControlBits = SetBit, //needs to be changed regarding flow of TCP!

                Window = 100,
                Checksum = null, //Will be filled automatically
                UrgentPointer = 0,
                Options = TcpOptions.None
            };
            return tcpLayer;
        }

        public static List<Layer> GetTcpReplyPacket(MacAddress MacAddressLocal, MacAddress MacAddressRemote, IpV4Address SourceIP, IpV4Address DestinationIP, TcpLayer tcpLayer) //create legacy "datagram" which is going to be sent back
        {
            if (tcpLayer == null) { return null; } //extra protection

            List<Layer> layers = new List<Layer>(); //list of used layers
            layers.Add(GetEthernetLayer(MacAddressLocal, MacAddressRemote)); //L2
            layers.Add(GetIpV4Layer(SourceIP, DestinationIP));
            layers.Add(tcpLayer);
            return (layers);
        }

        public static uint GetSynOrAckRandNumber() //for generating random SYN and ACK numbers
        {
            //effectively random; it may be any value between 0 and 4,294,967,295 (?) inclusive. 
            uint generatedNum = (ushort)rand.Next(0, 65535);
            return generatedNum;
        }

        public static Packet CatchTcpReply(IpV4Address SourceIpV4, IpV4Address DestinationIpV4, ushort _sourcePort, ushort _destinationPort, uint ackNumberExpected, TcpControlBits waitForBit) //parametres are switching inside method, not in call
        {
            PcapDotNet.Core.PacketDevice selectedDevice = NetDevice.GetSelectedDevice(SourceIpV4); //take the selected adapter
            using (PcapDotNet.Core.PacketCommunicator communicator = selectedDevice.Open(65536, PcapDotNet.Core.PacketDeviceOpenAttributes.Promiscuous, 1000))
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
                            return packet; //send back packet which we are waiting as an answer
                        }
                    }

                    if (sw.ElapsedMilliseconds > TcpTimeoutInMs) //timeout break
                    {
                        sw.Stop();
                        return null;
                    }
                }
            }
        }

        //---------L7------------------------------------------------------------------------------------------------------------
        public static DnsLayer GetDnsHeaderLayer(ushort id = 65535)
        {
            if (id == 65535)
            {
                id = (ushort)rand.Next(0, 65535);
            }

            //knowledge in RFC1035 >>> layers: Header AND (Question OR Answer OR Authority OR Additional)
            DnsLayer dnsLayer = new DnsLayer
            {
                Id = id,                          //16 bit identifier assigned by the program; is copied to the corresponding reply
                IsResponse = false,               //message is a query(0), or a response(1).
                OpCode = DnsOpCode.Query,         //specifies kind of query in this message. This value is set by the originator of a query and copied into the response.
                IsAuthoritativeAnswer = true,     //responding name server is an  authority for the domain name in question section.
                IsTruncated = false,              //was shortened than permitted value on the channel
                IsRecursionDesired = true,        //may be set in a query and is copied into the response; name server try to pursue the query recursively
                IsRecursionAvailable = true,      //this be is set or cleared in a response
                FutureUse = false,                //Must be zero in all queries and responses. (3 bits)
                IsAuthenticData = true,
                IsCheckingDisabled = false,
                ResponseCode = DnsResponseCode.NoError,   //4 bit field  as part of responses //Values 6-15 Reserved for future use.
                Queries = null,
                Answers = null,
                Authorities = null,
                Additionals = null,
                DomainNameCompressionMode = DnsDomainNameCompressionMode.Nothing //should be suspicious, original = All
            };
            return dnsLayer;
        }

        public static DnsQueryResourceRecord GetDnsQuery(string domainName, DnsType type = DnsType.A)
        {
            return new DnsQueryResourceRecord(new DnsDomainName(domainName), type, DnsClass.Internet);
            //DnsType = code of the query (A/CNAME...) https://en.wikipedia.org/wiki/List_of_DNS_record_types
        }

        public static DnsDataResourceRecord GetDnsAnswer(DnsDomainName domainName, DnsType type, string ipaddressOrText)
        {
            int ttl = 3600;
            if (type == DnsType.A || type == DnsType.Aaaa) //warning: mixing types
            {
                if (IPAddress.TryParse(ipaddressOrText, out IPAddress address))
                {
                    return new DnsDataResourceRecord(domainName, type, DnsClass.Internet, ttl, new DnsResourceDataIpV4(new IpV4Address(address.ToString())));
                }
            }
            else if (type == DnsType.Txt) //why
            {
                return new DnsDataResourceRecord(domainName, DnsType.Txt, DnsClass.Internet, ttl, new DnsResourceDataText(new[] { new DataSegment(Encoding.ASCII.GetBytes(ipaddressOrText)) }.AsReadOnly()));
            }
            else
            {
                return new DnsDataResourceRecord(domainName, DnsType.Any, DnsClass.Internet, ttl, new DnsResourceDataAnything(DataSegment.Empty));
            }

            //TODO more types

            return null;
        }

        public static List<Layer> GetDnsPacket(MacAddress macAddressLocal, MacAddress macAddressRemote, IpV4Address ipLocalListening, IpV4Address ipRemoteSpeaker, ushort portLocal, ushort portRemote, DnsDatagram dns)
        {
            if (dns == null) { return null; } //extra protection

            //create legacy "datagram" which is going to be sent back
            List<Layer> layers = new List<Layer>(); //list of used layers
            layers.Add(GetEthernetLayer(macAddressLocal, macAddressRemote)); //L2
            layers.Add(GetIpV4Layer(ipLocalListening, ipRemoteSpeaker));
            layers.Add(GetUdpLayer(portLocal, portRemote));

            DnsLayer dnsLayer = GetDnsHeaderLayer(dns.Id);
            if (dns.IsQuery) //if its DNS request...
            {
                dnsLayer.IsResponse = true;
                List<DnsDataResourceRecord> answers = new List<DnsDataResourceRecord>(); //used for collecting answers if they came in list
                dnsLayer.Queries = dns.Queries; //include original request
                foreach (DnsQueryResourceRecord query in dns.Queries)
                {
                    Stopwatch sw = new Stopwatch(); //for timeout of DNS request
                    sw.Start();
                    IpV4Address iptranslated = new IpV4Address();

                    bool waitForDns = true;
                    while (waitForDns)
                    {
                        iptranslated = GetDnsIpFromHostnameReal(query.DomainName.ToString());
                        if (sw.ElapsedMilliseconds > DnsTimeoutInMs/2) //timeout break //SLOW
                        {
                            sw.Stop();
                            waitForDns = false;
                            if (iptranslated.ToString().Equals(""))
                            {
                                iptranslated = new IpV4Address("208.67.220.220"); //backup answer
                                break;
                            }
                        }
                    }

                    answers.Add(NetStandard.GetDnsAnswer(query.DomainName, query.DnsType, iptranslated.ToString()));

                    //TODO answer for IPv6                                       
                }
                dnsLayer.Answers = answers;
            }

            //TODO more answers possible

            layers.Add(dnsLayer);
            return (layers);
        }

        public static IpV4Address GetDnsIpFromHostnameReal(string hostname) //oficial DNS service, returns sample in case of failure //simplifying
        {
            IPHostEntry host;
            try
            {
                host = Dns.GetHostEntry(hostname);
            }
            catch
            {
                host = null; //TODO WARNING to implement
            }

            if (host != null && IPAddress.TryParse(host.AddressList[0].ToString(), out IPAddress address))
            {
                switch (address.AddressFamily)
                {
                    case System.Net.Sockets.AddressFamily.InterNetwork:
                        break;
                    default:
                        address = IPAddress.Parse("208.67.222.222"); //TODO not good hardcoded IP
                        break;
                }
            }
            else
            {
                //we probably dont know reply to everything what is comming...
                //TODO found how to recognize "can't find X: Non-existent domain" and solve...
                address = System.Net.IPAddress.Parse("208.67.222.222"); //openDNS IP
            }

            return new IpV4Address(address.ToString()); //TODO - like a pro, sry
        }

        //GetHttpPacket
        public static List<Layer> GetHttpPacket(MacAddress macAddressLocal, MacAddress macAddressRemote, IpV4Address ipLocalListening, IpV4Address ipRemoteSpeaker, ushort portLocal, ushort portRemote, TcpLayer tcpLayer, HttpDatagram http)
        {
            if (http == null) { return null; } //extra protection

            //create legacy "datagram" which is going to be sent back
            List<Layer> layers = new List<Layer>(); //list of used layers
            layers.Add(GetEthernetLayer(macAddressLocal, macAddressRemote)); //L2
            layers.Add(GetIpV4Layer(ipLocalListening, ipRemoteSpeaker)); //L3

            //if TcpDatagram tcp == typeOf(TcpDatagram)
            //TcpLayer tcpLayer = GetTcpLayer(tcp.SourcePort, tcp.DestinationPort, tcp.SequenceNumber, tcp.AcknowledgmentNumber, tcp.ControlBits); //L4
            layers.Add(tcpLayer); //L4

            HttpLayer httpLayer = new HttpResponseLayer();
            if (http.IsRequest)
            {
                httpLayer = new HttpResponseLayer
                {
                    Version = PcapDotNet.Packets.Http.HttpVersion.Version11,
                    StatusCode = 200,
                    ReasonPhrase = new DataSegment(Encoding.ASCII.GetBytes("OK")),
                    Header = new HttpHeader(new HttpContentLengthField(10)),
                    Body = new Datagram(new byte[10])
                };

                //TODO implement some better answers...
            }

            layers.Add(httpLayer);
            return layers;
        }
    }
}