using PcapDotNet.Base;
using PcapDotNet.Core;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Dns;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.Http;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.Transport;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;
using System.Diagnostics;

namespace SteganographyFramework
{
    public static class NetworkMethods
    {
        //---------L2------------------------------------------------------------------------------------------------------------
        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        private static extern int SendARP(int DestIP, int SrcIP, byte[] pMacAddr, ref uint PhyAddrLen);
        public static MacAddress getDestinationMacAddress(IpV4Address ipAddress) //because destination mac address needs to be requested for network
        {
            if (ipAddress == null) //in case of input problem
            {
                ipAddress = new IpV4Address(GetDefaultGateway().ToString()); //get alternative default gateway ip
            }

            MacAddress macAddress;
            try
            {
                //source: https://stephenhaunts.com/2014/01/06/getting-the-mac-address-for-a-machine-on-the-network/
                byte[] macAddr = new byte[6];
                uint macAddrLen = (uint)macAddr.Length;
                int intAddress = BitConverter.ToInt32(IPAddress.Parse(ipAddress.ToString()).GetAddressBytes(), 0);
                string[] str = new string[(int)macAddrLen];

                for (int i = 0; i < macAddrLen; i++)
                {
                    str[i] = macAddr[i].ToString("x2");
                }

                macAddress = new MacAddress(string.Join(":", str).ToUpper()); //get L2 destination address for inserted IP address                
            }
            catch
            {
                macAddress = new MacAddress("02:02:02:02:02:02"); //should be less suspicious

            }

            return macAddress;
        }
        public static EthernetLayer GetEthernetLayer(MacAddress MacAddressSource, MacAddress MacAddressDestination)
        {
            EthernetLayer ethernetVrstva = new EthernetLayer();
            ethernetVrstva.Source = MacAddressSource;
            ethernetVrstva.Destination = MacAddressDestination;
            ethernetVrstva.EtherType = EthernetType.None; //Will be filled automatically.                            
            return ethernetVrstva;
        }

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

                    var gateway =
                        gateways.FirstOrDefault(g => g.Address.AddressFamily.ToString() == "InterNetwork");
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
            TcpLayer tcpLayer = new TcpLayer();
            tcpLayer.SourcePort = sourcePort;
            tcpLayer.DestinationPort = destinationPort;
            tcpLayer.SequenceNumber = sequenceNumber;
            tcpLayer.AcknowledgmentNumber = acknowledgmentNumber;
            tcpLayer.ControlBits = SetBit; //needs to be changed regarding flow of TCP!

            tcpLayer.Window = 100;
            tcpLayer.Checksum = null; //Will be filled automatically
            tcpLayer.UrgentPointer = 0;
            tcpLayer.Options = TcpOptions.None;
            return tcpLayer;
        }

        public static uint? WaitForTcpAck(PacketCommunicator communicator, IpV4Address SourceIpV4, IpV4Address DestinationIpV4, ushort _sourcePort, ushort _destinationPort, uint ackNumberExpected, TcpControlBits waitForBit = TcpControlBits.Acknowledgment)
        {
            communicator.SetFilter("tcp and src " + DestinationIpV4 + " and dst " + SourceIpV4 + " and src port " + _destinationPort + " and dst port " + _sourcePort);
            Stopwatch sw = new Stopwatch(); //for timeout
            sw.Start();

            while (true)
            {
                Packet packet;
                if (communicator.ReceivePacket(out packet) == PacketCommunicatorReceiveResult.Ok && packet.Ethernet.IpV4.Tcp.ControlBits == waitForBit)
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

        //---------L5------------------------------------------------------------------------------------------------------------
        //---------L6------------------------------------------------------------------------------------------------------------
        //---------L7------------------------------------------------------------------------------------------------------------

        //DNS
        public static DnsLayer GetDnsHeaderLayer(ushort id) //+hardcoded IP + hardo
        {
            DnsLayer dnsVrstva = new DnsLayer();        //knowledge in RFC1035, layers: Header AND (Question OR Answer OR Authority OR Additional)
            dnsVrstva.Id = id;                          //16 bit identifier assigned by the program; is copied to the corresponding reply
            dnsVrstva.IsResponse = false;               //message is a query(0), or a response(1).
            dnsVrstva.OpCode = DnsOpCode.Query;         //specifies kind of query in this message. This value is set by the originator of a query and copied into the response.
            dnsVrstva.IsAuthoritativeAnswer = true;     //responding name server is an  authority for the domain name in question section.
            dnsVrstva.IsTruncated = false;              //was shortened than permitted value on the channel
            dnsVrstva.IsRecursionDesired = true;        //may be set in a query and is copied into the response; name server try to pursue the query recursively
            dnsVrstva.IsRecursionAvailable = true;      //this be is set or cleared in a response
            dnsVrstva.FutureUse = false;                //Must be zero in all queries and responses. (3 bits)
            dnsVrstva.IsAuthenticData = true;
            dnsVrstva.IsCheckingDisabled = false;
            dnsVrstva.ResponseCode = DnsResponseCode.NoError;   //4 bit field  as part of responses //Values 6-15 Reserved for future use.
            dnsVrstva.Queries = null;
            dnsVrstva.Answers = null;
            dnsVrstva.Authorities = null;
            dnsVrstva.Additionals = null;
            dnsVrstva.DomainNameCompressionMode = DnsDomainNameCompressionMode.Nothing; //should be suspicious, original = All
            return dnsVrstva;
        }
        public static DnsQueryResourceRecord GetDnsQuery(string domainName, DnsType type = DnsType.A)
        {
            return new DnsQueryResourceRecord(new DnsDomainName(domainName), type, DnsClass.Internet);
            //DnsType = code of the query (A/CNAME...) https://en.wikipedia.org/wiki/List_of_DNS_record_types
        }
        public static DnsDataResourceRecord GetDnsAnswer(DnsDomainName domainName, DnsType type, string ipaddressOrText)
        {
            int ttl = 3600;
            if (type == DnsType.A)
            {
                IPAddress address;
                if (IPAddress.TryParse(ipaddressOrText, out address))
                {
                    return new DnsDataResourceRecord(domainName, DnsType.A, DnsClass.Internet, ttl, new DnsResourceDataIpV4(new IpV4Address(address.ToString())));
                }

                //missing else

            }
            else if (type == DnsType.Txt)
            {
                return new DnsDataResourceRecord(domainName, DnsType.Txt, DnsClass.Internet, ttl, new DnsResourceDataText(new[] { new DataSegment(Encoding.ASCII.GetBytes(ipaddressOrText)) }.AsReadOnly()));
            }

            //more types should be implemented

            return null;
        }
        public static DnsDataResourceRecord GetDnsAuthority(string domainName)
        {
            int ttl = 3600;
            return new DnsDataResourceRecord(new DnsDomainName(domainName), DnsType.MailExchange, DnsClass.Internet, ttl, new DnsResourceDataMailExchange(100, new DnsDomainName(domainName))); //it is correct or enought general?
        }
        public static DnsDataResourceRecord GetDnsAdditional(string domainName)
        {
            ushort ttl = 3600;
            return new DnsOptResourceRecord(new DnsDomainName(domainName), ttl, 0, DnsOptVersion.Version0, DnsOptFlags.DnsSecOk,
                   new DnsResourceDataOptions(new DnsOptions(new DnsOptionUpdateLease(100), new DnsOptionLongLivedQuery(1, DnsLongLivedQueryOpCode.Refresh, DnsLongLivedQueryErrorCode.NoError, 10, 20))));
        }
        public static IpV4Address getIPfromHostnameViaDNS(string hostname) //oficial DNS service, returns sample in case of failure //simplifying
        {
            IPHostEntry host;
            try
            {
                host = Dns.GetHostEntry(hostname);
            }
            catch
            {
                host = null;
                //TODO WARNING implement
            }

            IPAddress address;
            if (host != null && IPAddress.TryParse(host.AddressList[0].ToString(), out address))
            {
                switch (address.AddressFamily)
                {
                    case System.Net.Sockets.AddressFamily.InterNetwork:
                        break;
                    default:
                        address = IPAddress.Parse("208.67.222.222");
                        break;
                }
            }
            else
            {
                address = System.Net.IPAddress.Parse("208.67.222.222"); //openDNS IP
            }

            return new IpV4Address(address.ToString()); //like a pro, sry
        }
        public static List<IpV4Address> getIPsListfromHostnameViaDNS(string hostname) //another attemp for DNS service, not used
        {
            IPAddress[] ips;
            ips = Dns.GetHostAddresses(hostname);

            ///source https://msdn.microsoft.com/en-us/library/system.net.dns.gethostaddresses.aspx

            List<IpV4Address> ipaddresses = new List<IpV4Address>();
            foreach (IPAddress ip in ips)
            {
                ipaddresses.Add(new IpV4Address(ip.ToString()));
            }

            return ipaddresses;
        }

        //HTTP
        private static HttpLayer GetHttpGet(string host) //unfinished
        {
            // HTTP Layer
            HttpLayer httpLayer = new HttpRequestLayer();
            //httpLayer.Uri = "/";
            httpLayer.Header = new HttpHeader(HttpField.CreateField("Host", host));
            //httpLayer.Method = new HttpRequestMethod(HttpRequestKnownMethod.Get);
            httpLayer.Version = PcapDotNet.Packets.Http.HttpVersion.Version11;

            return httpLayer;
            //nessesary to do! _expectedAckNumber = (uint)(_seqNumber + packet.Ethernet.IpV4.Tcp.PayloadLength);
        }
        //---------Universal-----------------------------------------------------------------------------------------------------        
    }
}

