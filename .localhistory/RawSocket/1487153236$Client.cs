using PcapDotNet.Core;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using PcapDotNet.Base;
using PcapDotNet.Core;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Arp;
using PcapDotNet.Packets.Dns;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.Gre;
using PcapDotNet.Packets.Http;
using PcapDotNet.Packets.Icmp;
using PcapDotNet.Packets.Igmp;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.IpV6;
using PcapDotNet.Packets.Transport;
using System.Windows.Forms;

namespace RawSocket
{
    public class Client
    {
        public volatile bool terminate = false;

        private MainWindow mv; //not good

        public string SourceIP { get; set; }
        public string DestinationIP { get; set; }
        public string StegoMethod { get; set; } //contains name of choosen method
        public string Secret { get; set; } //contains magic to be transferred

        public Client(MainWindow mv)
        {
            this.mv = mv;
        }
        public void Speaking()
        {
            do
            {
                Lib.selectedDevice = Lib.allDevices[Lib.getSelectedInterfaceIndex(SourceIP)]; // Take the selected adapter

                //name of the device //size // promiscuous mode // read timeout
                using (PacketCommunicator communicator = Lib.selectedDevice.Open(100, PacketDeviceOpenAttributes.Promiscuous, 1000))
                {

                    if (String.Equals(StegoMethod, "ICMP payload"))
                    {

                    }
                    else if (String.Equals(StegoMethod, "IPv4 manipulation"))
                    {

                    }
                    else if (String.Equals(StegoMethod, "TCP manipulation"))
                    {
                        /* ODSTAVENO, bude složit pro modifikaci, standardní funkce BuildCOSIG by měly posílat korektní packety, zde se případně postaví speciality v nějakém cyklu a vloží se do standardních vrstev
                        TcpLayer tcpLayer = new TcpLayer
                        {
                            SourcePort = UInt16.Parse(numericUpDownClientPort.Value.ToString()),
                            DestinationPort = UInt16.Parse(numericUpDownServerPort.Value.ToString()),
                            Checksum = null, // Will be filled automatically.
                            SequenceNumber = 20170213,
                            ControlBits = TcpControlBits.Acknowledgment,
                            UrgentPointer = 0,
                            Options = TcpOptions.None,
                        };

                        PayloadLayer payloadLayer = new PayloadLayer
                        {
                            Data = new Datagram(Encoding.ASCII.GetBytes("hello world")),
                        };

                        PacketBuilder builder = new PacketBuilder(tcpLayer, payloadLayer);  //Additional information: First layer (PcapDotNet.Packets.Transport.TcpLayer) must provide a DataLink
                        */

                        communicator.SendPacket(BuildTcpPacket(Secret));

                    }
                    else
                    {
                        SettextBoxDebug("Nothing happened\n");
                    }
                }
            }
            while (!terminate);
        }

        public void SettextBoxDebug(string text)
        {
            mv.Invoke((MethodInvoker)delegate
            {
                mv.textBoxDebug.Text = text + mv.textBoxDebug.Text; // runs on UI thread
            });

            //reason: Operace mezi vlákny není platná: Přístup k ovládacímu prvku textBoxDebug proběhl z jiného vlákna než z vlákna, v rámci kterého byl vytvořen.
        }

        public void Terminate()
        {
            this.terminate = true;
        }

        /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        public static EthernetLayer BuildEthernetLayer()
        {
            EthernetLayer ethernetLayer = new EthernetLayer
            {
                Source = new MacAddress("01:01:01:01:01:01"), //TODO use real or remove this block...
                Destination = new MacAddress("02:02:02:02:02:02"),
                EtherType = EthernetType.None, // Will be filled automatically.
            };

            return (ethernetLayer);
        }

        public IpV4Layer BuildipV4Layer()//default argument
        {
            IpV4Layer IpV4Layer = new IpV4Layer()
            {
                Source = new IpV4Address(SourceIP),
                CurrentDestination = new IpV4Address(DestinationIP),
                Fragmentation = IpV4Fragmentation.None,
                HeaderChecksum = null, // Will be filled automatically.
                //Identification = 123,
                Options = IpV4Options.None,
                Protocol = IpV4Protocol.Tcp, //option 6
                Ttl = 100,
                TypeOfService = 0,
            };

            return IpV4Layer;
        }

        public static PayloadLayer BuildpayloadLayer(string payload)
        {
            PayloadLayer payloadLayer;
            if (payload == null)
            {
                payloadLayer = new PayloadLayer
                {
                    Data = new Datagram(Encoding.ASCII.GetBytes("samplePayload")),
                };
                //Additional information: String reference not set to an instance of a String.
                //Additional information: Odkaz na řetězec nebyl nastaven na instanci proměnné String.
            }
            else
            {
                payloadLayer = new PayloadLayer
                {
                    Data = new Datagram(Encoding.ASCII.GetBytes(payload)),
                };                
            }
            return payloadLayer;
        }

        private static TcpLayer BuildTcpLayer()
        {
            TcpLayer tcpLayer = new TcpLayer()
            {
                SourcePort = 4050,
                DestinationPort = 25,
                Checksum = null, // Will be filled automatically.
                SequenceNumber = 100,
                AcknowledgmentNumber = 50,
                ControlBits = TcpControlBits.Acknowledgment,
                Window = 100,
                UrgentPointer = 0,
                Options = TcpOptions.None,
            };

            return tcpLayer;
        }

        private static Packet BuildEthernetPacket(string payload) /// This function build an Ethernet with payload packet.
        {
            EthernetLayer ethernetLayer = BuildEthernetLayer();
            PayloadLayer payloadLayer = BuildpayloadLayer(payload);
            PacketBuilder builder = new PacketBuilder(ethernetLayer, payloadLayer);
            return builder.Build(DateTime.Now);
        }

        private Packet BuildIpV4Packet(string payload) /// This function build an IPv4 over Ethernet with payload packet.
        {
            EthernetLayer ethernetLayer = BuildEthernetLayer();
            IpV4Layer ipV4Layer = BuildipV4Layer();
            PayloadLayer payloadLayer = BuildpayloadLayer(payload);

            PacketBuilder builder = new PacketBuilder(ethernetLayer, ipV4Layer, payloadLayer);
            return builder.Build(DateTime.Now);
        }



        private static Packet BuildIcmpPacket() /// This function build an ICMP over IPv4 over Ethernet packet.
        {
            EthernetLayer ethernetLayer = BuildEthernetLayer();

            //nonostandard ipv4 layer, how to make it just change of standard? it doesnt work ipV4Layer.Identification
            IpV4Layer ipV4Layer = new IpV4Layer
            {
                Source = new IpV4Address("1.2.3.4"),
                CurrentDestination = new IpV4Address("11.22.33.44"),
                Fragmentation = IpV4Fragmentation.None,
                HeaderChecksum = null, // Will be filled automatically.
                Identification = 123,
                Options = IpV4Options.None,
                Protocol = null, // Will be filled automatically.
                Ttl = 100,
                TypeOfService = 0,
            };

            IcmpEchoLayer icmpLayer = new IcmpEchoLayer
            {
                Checksum = null, // Will be filled automatically.
                Identifier = 456,
                SequenceNumber = 800,
            };

            PacketBuilder builder = new PacketBuilder(ethernetLayer, ipV4Layer, icmpLayer);
            return builder.Build(DateTime.Now);
        }

        private Packet BuildTcpPacket(string payload) /// This function build an TCP over IPv4 over Ethernet with payload packet.
        {
            EthernetLayer ethernetLayer = BuildEthernetLayer();
            IpV4Layer ipV4Layer = BuildipV4Layer();
            TcpLayer tcpLayer = BuildTcpLayer();
            PayloadLayer payloadLayer = BuildpayloadLayer(payload);

            PacketBuilder builder = new PacketBuilder(ethernetLayer, ipV4Layer, tcpLayer, payloadLayer);
            return builder.Build(DateTime.Now);
        }

        private Packet BuildDnsPacket() /// This function build a DNS over UDP over IPv4 over Ethernet packet. //nonfinished
        {
            EthernetLayer ethernetLayer = BuildEthernetLayer();
            IpV4Layer ipV4Layer = BuildipV4Layer();

            UdpLayer udpLayer = new UdpLayer
            {
                SourcePort = 4050,
                DestinationPort = 53,
                Checksum = null, // Will be filled automatically.
                CalculateChecksumValue = true,
            };

            DnsLayer dnsLayer = new DnsLayer
            {
                Id = 100,
                IsResponse = false,
                OpCode = DnsOpCode.Query,
                IsAuthoritativeAnswer = false,
                IsTruncated = false,
                IsRecursionDesired = true,
                IsRecursionAvailable = false,
                FutureUse = false,
                IsAuthenticData = false,
                IsCheckingDisabled = false,
                ResponseCode = DnsResponseCode.NoError,
                Queries = new[]
                                      {
                                          new DnsQueryResourceRecord(new DnsDomainName("pcapdot.net"), DnsType.A, DnsClass.Internet),
                                      },
                Answers = null,
                Authorities = null,
                Additionals = null,
                DomainNameCompressionMode = DnsDomainNameCompressionMode.All,
            };

            PacketBuilder builder = new PacketBuilder(ethernetLayer, ipV4Layer, udpLayer, dnsLayer);

            return builder.Build(DateTime.Now);
        }
        private static Packet BuildHttpPacket() /// This function build an HTTP over TCP over IPv4 over Ethernet packet. //nonfinished
        {
            EthernetLayer ethernetLayer = new EthernetLayer
            {
                Source = new MacAddress("01:01:01:01:01:01"),
                Destination = new MacAddress("02:02:02:02:02:02"),
                EtherType = EthernetType.None, // Will be filled automatically.
            };

            IpV4Layer ipV4Layer = new IpV4Layer
            {
                Source = new IpV4Address("1.2.3.4"),
                CurrentDestination = new IpV4Address("11.22.33.44"),
                Fragmentation = IpV4Fragmentation.None,
                HeaderChecksum = null, // Will be filled automatically.
                Identification = 123,
                Options = IpV4Options.None,
                Protocol = null, // Will be filled automatically.
                Ttl = 100,
                TypeOfService = 0,
            };

            TcpLayer tcpLayer = new TcpLayer
            {
                SourcePort = 4050,
                DestinationPort = 80,
                Checksum = null, // Will be filled automatically.
                SequenceNumber = 100,
                AcknowledgmentNumber = 50,
                ControlBits = TcpControlBits.Acknowledgment,
                Window = 100,
                UrgentPointer = 0,
                Options = TcpOptions.None,
            };

            HttpRequestLayer httpLayer = new HttpRequestLayer
            {
                Version = PcapDotNet.Packets.Http.HttpVersion.Version11, //conflict with standard method
                Header = new HttpHeader(new HttpContentLengthField(11)),
                Body = new Datagram(Encoding.ASCII.GetBytes("hello world")),
                Method = new HttpRequestMethod(HttpRequestKnownMethod.Get),
                Uri = @"http://pcapdot.net/",
            };

            PacketBuilder builder = new PacketBuilder(ethernetLayer, ipV4Layer, tcpLayer, httpLayer);

            return builder.Build(DateTime.Now);
        }
        private static Packet BuildComplexPacket() /// This function build a DNS over UDP over IPv4 over GRE over IPv4 over IPv4 over VLAN Tagged Frame over VLAN Tagged Frame over Ethernet. //nonrevised
        {
            return PacketBuilder.Build(DateTime.Now, new EthernetLayer
            {
                Source = new MacAddress("01:01:01:01:01:01"),
                Destination = new MacAddress("02:02:02:02:02:02"),
                EtherType = EthernetType.None, // Will be filled automatically.
            },
                new VLanTaggedFrameLayer
                {
                    PriorityCodePoint = ClassOfService.ExcellentEffort,
                    CanonicalFormatIndicator = false,
                    EtherType = EthernetType.None, // Will be filled automatically.
                },
                new VLanTaggedFrameLayer
                {
                    PriorityCodePoint = ClassOfService.BestEffort,
                    CanonicalFormatIndicator = false,
                    EtherType = EthernetType.None, // Will be filled automatically.
                },
                new IpV4Layer
                {
                    Source = new IpV4Address("1.2.3.4"),
                    CurrentDestination = new IpV4Address("11.22.33.44"),
                    Fragmentation = IpV4Fragmentation.None,
                    HeaderChecksum = null, // Will be filled automatically.
                    Identification = 123,
                    Options = IpV4Options.None,
                    Protocol = null, // Will be filled automatically.
                    Ttl = 100,
                    TypeOfService = 0,
                },
                new IpV4Layer
                {
                    Source = new IpV4Address("5.6.7.8"),
                    CurrentDestination = new IpV4Address("55.66.77.88"),
                    Fragmentation = IpV4Fragmentation.None,
                    HeaderChecksum = null, // Will be filled automatically.
                    Identification = 456,
                    Options = new IpV4Options(new IpV4OptionStrictSourceRouting(
                                                      new[]
                                                          {
                                                              new IpV4Address("100.200.100.200"),
                                                              new IpV4Address("150.250.150.250")
                                                          }, 1)),
                    Protocol = null, // Will be filled automatically.
                    Ttl = 200,
                    TypeOfService = 0,
                },
                new GreLayer
                {
                    Version = GreVersion.Gre,
                    ProtocolType = EthernetType.None, // Will be filled automatically.
                    RecursionControl = 0,
                    FutureUseBits = 0,
                    ChecksumPresent = true,
                    Checksum = null, // Will be filled automatically.
                    Key = 100,
                    SequenceNumber = 123,
                    AcknowledgmentSequenceNumber = null,
                    RoutingOffset = null,
                    Routing = new[]
                                      {
                                          new GreSourceRouteEntryIp(
                                              new[]
                                                  {
                                                      new IpV4Address("10.20.30.40"),
                                                      new IpV4Address("40.30.20.10")
                                                  }.AsReadOnly(), 1),
                                          new GreSourceRouteEntryIp(
                                              new[]
                                                  {
                                                      new IpV4Address("11.22.33.44"),
                                                      new IpV4Address("44.33.22.11")
                                                  }.AsReadOnly(), 0)
                                      }.Cast<GreSourceRouteEntry>().ToArray().AsReadOnly(),
                    StrictSourceRoute = false,
                },
                new IpV4Layer
                {
                    Source = new IpV4Address("51.52.53.54"),
                    CurrentDestination = new IpV4Address("61.62.63.64"),
                    Fragmentation = IpV4Fragmentation.None,
                    HeaderChecksum = null, // Will be filled automatically.
                    Identification = 123,
                    Options = new IpV4Options(
                            new IpV4OptionTimestampOnly(0, 1,
                                                        new IpV4TimeOfDay(new TimeSpan(1, 2, 3)),
                                                        new IpV4TimeOfDay(new TimeSpan(15, 55, 59))),
                            new IpV4OptionQuickStart(IpV4OptionQuickStartFunction.RateRequest, 10, 200, 300)),
                    Protocol = null, // Will be filled automatically.
                    Ttl = 100,
                    TypeOfService = 0,
                },
                new UdpLayer
                {
                    SourcePort = 53,
                    DestinationPort = 40101,
                    Checksum = null, // Will be filled automatically.
                    CalculateChecksumValue = true,
                },
                new DnsLayer
                {
                    Id = 10012,
                    IsResponse = true,
                    OpCode = DnsOpCode.Query,
                    IsAuthoritativeAnswer = true,
                    IsTruncated = false,
                    IsRecursionDesired = true,
                    IsRecursionAvailable = true,
                    FutureUse = false,
                    IsAuthenticData = true,
                    IsCheckingDisabled = false,
                    ResponseCode = DnsResponseCode.NoError,
                    Queries =
                            new[]
                                {
                                    new DnsQueryResourceRecord(
                                        new DnsDomainName("pcapdot.net"),
                                        DnsType.Any,
                                        DnsClass.Internet),
                                },
                    Answers =
                            new[]
                                {
                                    new DnsDataResourceRecord(
                                        new DnsDomainName("pcapdot.net"),
                                        DnsType.A,
                                        DnsClass.Internet
                                        , 50000,
                                        new DnsResourceDataIpV4(new IpV4Address("10.20.30.44"))),
                                    new DnsDataResourceRecord(
                                        new DnsDomainName("pcapdot.net"),
                                        DnsType.Txt,
                                        DnsClass.Internet,
                                        50000,
                                        new DnsResourceDataText(new[] {new DataSegment(Encoding.ASCII.GetBytes("Pcap.Net"))}.AsReadOnly()))
                                },
                    Authorities =
                            new[]
                                {
                                    new DnsDataResourceRecord(
                                        new DnsDomainName("pcapdot.net"),
                                        DnsType.MailExchange,
                                        DnsClass.Internet,
                                        100,
                                        new DnsResourceDataMailExchange(100, new DnsDomainName("pcapdot.net")))
                                },
                    Additionals =
                            new[]
                                {
                                    new DnsOptResourceRecord(
                                        new DnsDomainName("pcapdot.net"),
                                        50000,
                                        0,
                                        DnsOptVersion.Version0,
                                        DnsOptFlags.DnsSecOk,
                                        new DnsResourceDataOptions(
                                            new DnsOptions(
                                                new DnsOptionUpdateLease(100),
                                                new DnsOptionLongLivedQuery(1,
                                                                            DnsLongLivedQueryOpCode.Refresh,
                                                                            DnsLongLivedQueryErrorCode.NoError,
                                                                            10, 20))))
                                },
                    DomainNameCompressionMode = DnsDomainNameCompressionMode.All,
                });
        }
    }
}
