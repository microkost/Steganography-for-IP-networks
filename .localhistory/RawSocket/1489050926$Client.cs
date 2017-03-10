using PcapDotNet.Core;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using PcapDotNet.Base;
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
        public string StegoMethod { get; set; } //contains name of choosen method
        public string Secret { get; set; } //contains magic to be transferred

        private MainWindow mv; //not good

        //---NETWORKING PARAMETRES---//
        public string SourceIP { get; set; }
        public string DestinationIP { get; set; }
        public ushort DestinationPort { get; set; }
        public ushort SourcePort { get; set; }
        public MacAddress MacAddressSource { get; set; }
        public MacAddress MacAddressDestination { get; set; }

        public Client(MainWindow mv)
        {
            this.mv = mv;
            MacAddressSource = new MacAddress("01:01:01:01:01:01"); //replace by real one here or after selecting interface //now debug values
            MacAddressDestination = new MacAddress("02:02:02:02:02:02");
        }
        public void Speaking()
        {
            Lib.selectedDevice = Lib.allDevices[Lib.getSelectedInterfaceIndex(SourceIP)]; // Take the selected adapter //Additional information: Index was out of range. Must be non-negative and less than the size of the collection.
            bool isSomethingToSay = true;
            do //to controll thread
            {
                if (Secret == null) //when there is no secret to transferr (wrong initialization)
                    break;

                if (isSomethingToSay) //to control transmission
                {
                    using (PacketCommunicator communicator = Lib.selectedDevice.Open(100, PacketDeviceOpenAttributes.Promiscuous, 1000)) //name of the device //size // promiscuous mode // read timeout
                    {
                        if (String.Equals(StegoMethod, Lib.listOfStegoMethods[0])) //ICMP
                        {
                            //SendPacketTMP.sending(Lib.getSelectedInterfaceIndex(SourceIP));

                            //2 Ethernet Layer
                            MacAddress source = new MacAddress("01:01:01:01:01:01"); // Supposing to be on ethernet
                            MacAddress destination = new MacAddress("02:02:02:02:02:02");
                            EthernetLayer ethernetLayer = new EthernetLayer
                            {
                                Source = source,
                                Destination = destination
                            };

                            //3 IPv4 Layer
                            IpV4Layer ipV4Layer = new IpV4Layer
                            {
                                Source = new IpV4Address(SourceIP),
                                CurrentDestination = new IpV4Address(DestinationIP),
                                Ttl = 255,
                                // The rest of the important parameters will be set for each packet
                            };

                            //4 ICMP Layer
                            IcmpEchoLayer icmpLayer = new IcmpEchoLayer();

                            // Create the builder that will build our packets
                            PacketBuilder builder = new PacketBuilder(ethernetLayer, ipV4Layer, icmpLayer);

                            // Send 100 Pings to different destination with different parameters
                            for (int i = 0; i != 100; ++i)
                            {
                                // Set IPv4 parameters
                                ipV4Layer.Identification = (ushort)i;

                                //DO SOME STEGANOGRAPHY! //<---------------------------------------------------------

                                // Set ICMP parameters
                                icmpLayer.SequenceNumber = (ushort)i;
                                icmpLayer.Identifier = (ushort)i;

                                // Build the packet
                                Packet packet = builder.Build(DateTime.Now);

                                // Send down the packet
                                communicator.SendPacket(packet);
                            }

                            SettextBoxDebug("Sent 100 pings\n");

                        }
                        else if (String.Equals(StegoMethod, Lib.listOfStegoMethods[1])) //TCP
                        {
                            List<Packet> stegosent = new List<Packet>(); //debug only

                            //2
                            EthernetLayer ethernetLayer = new EthernetLayer();
                            ethernetLayer.Source = MacAddressSource;
                            ethernetLayer.Destination = MacAddressDestination;
                            ethernetLayer.EtherType = EthernetType.None;

                            //3
                            IpV4Layer ipV4Layer = new IpV4Layer();
                            IpV4Layer ipv4Vrstva = new IpV4Layer();
                            ipv4Vrstva.TypeOfService = Convert.ToByte(0); //STEGO ready //0 default value
                            ipv4Vrstva.Source = new IpV4Address(SourceIP);
                            ipv4Vrstva.CurrentDestination = new IpV4Address(DestinationIP); //ipv4Vrstva.Destination is read only
                            ipv4Vrstva.Fragmentation = IpV4Fragmentation.None;
                            ipv4Vrstva.HeaderChecksum = null; //Will be filled automatically.
                            ipv4Vrstva.Identification = 555; //STEGO
                            ipv4Vrstva.Options = IpV4Options.None;
                            ipv4Vrstva.Protocol = IpV4Protocol.Tcp; //set ISN
                            ipv4Vrstva.Ttl = 100;

                            //4
                            TcpLayer tcpLayer = new TcpLayer //= BuildTcpLayer();
                            {
                                SourcePort = (ushort)SourcePort,
                                DestinationPort = (ushort)DestinationPort,
                                SequenceNumber = 2017,
                                ControlBits = TcpControlBits.Synchronize, //WHEN ACK as first then making troubles!                                
                            };

                            PacketBuilder builder = new PacketBuilder(ethernetLayer, ipV4Layer, tcpLayer);

                            char[] secretmessage = Secret.ToCharArray();
                            foreach (char c in secretmessage)
                            {
                                ipV4Layer.TypeOfService = Convert.ToByte((int)c); //TODO some extra protection
                                Packet packet = builder.Build(DateTime.Now);
                                stegosent.Add(packet);
                            }

                            foreach (Packet p in stegosent)
                            {
                                communicator.SendPacket(p);
                                System.Threading.Thread.Sleep(200);
                            }

                            SettextBoxDebug(String.Format("Sent {0}", Lib.listOfStegoMethods[1].ToString()));
                            terminate = true;
                        }
                        else if (String.Equals(StegoMethod, Lib.listOfStegoMethods[2])) //IP
                        {
                            SettextBoxDebug("IP not implemented\n");
                        }
                        else if (String.Equals(StegoMethod, Lib.listOfStegoMethods[3])) //ISN + IP ID
                        {
                            SettextBoxDebug("We are processing steganograpfy in ISN + IPID fields\n");
                            List<Packet> stegosent = new List<Packet>(); //debug only

                            //nessesary to do TCP handshake
                            //SYN paket obsahuje prázdný TCP segment a má nastavený příznak SYN v TCP hlavičce.                            

                            // Ethernet Layer
                            EthernetLayer ethernetVrstva = new EthernetLayer();
                            ethernetVrstva.Source = MacAddressSource;
                            ethernetVrstva.Destination = MacAddressDestination;
                            ethernetVrstva.EtherType = EthernetType.None; //Will be filled automatically.                            

                            // IPv4 Layer
                            IpV4Layer ipv4Vrstva = new IpV4Layer();
                            ipv4Vrstva.TypeOfService = Convert.ToByte(0); //STEGO ready //0 default value
                            ipv4Vrstva.Source = new IpV4Address(SourceIP);
                            ipv4Vrstva.CurrentDestination = new IpV4Address(DestinationIP); //ipv4Vrstva.Destination is read only
                            ipv4Vrstva.Fragmentation = IpV4Fragmentation.None;
                            ipv4Vrstva.HeaderChecksum = null; //Will be filled automatically.
                            //ipv4Vrstva.Identification = 555; //STEGO
                            ipv4Vrstva.Options = IpV4Options.None;
                            ipv4Vrstva.Protocol = IpV4Protocol.Tcp; //set ISN
                            ipv4Vrstva.Ttl = 100;

                            //needs to be finalize? //ipv4Vrstva.Finalize();

                            // TCPv4 Layer
                            TcpLayer tcpVrstva = new TcpLayer();
                            tcpVrstva.SourcePort = SourcePort;
                            tcpVrstva.DestinationPort = DestinationPort;
                            //tcpVrstva.SequenceNumber = Convert.ToUInt32(Secret[1]); //STEGO
                            tcpVrstva.AcknowledgmentNumber = 50;
                            tcpVrstva.ControlBits = TcpControlBits.Synchronize; //needs to be changed regarding flow
                            tcpVrstva.Window = 100;
                            tcpVrstva.Checksum = null; //Will be filled automatically?
                            tcpVrstva.UrgentPointer = 0;
                            tcpVrstva.Options = TcpOptions.None;

                            // Create the builder that will build our packets, build the packet, send the packet
                            PacketBuilder builder = new PacketBuilder(ethernetVrstva, ipv4Vrstva, tcpVrstva);
                            Packet packet = builder.Build(DateTime.Now);
                            communicator.SendPacket(packet);
                            stegosent.Add(packet);

                            /*
                            HttpRequestLayer httpVrstva = new HttpRequestLayer();
                            httpVrstva.Version = PcapDotNet.Packets.Http.HttpVersion.Version11; //conflict with standard method
                            httpVrstva.Header = new HttpHeader(new HttpContentLengthField(11));
                            httpVrstva.Body = new Datagram(Encoding.ASCII.GetBytes(Secret));
                            httpVrstva.Method = new HttpRequestMethod(HttpRequestKnownMethod.Get);
                            httpVrstva.Uri = @"http://pcapdot.net/";
                            */

                            //what about payload?
                            PayloadLayer payloadVrstva = new PayloadLayer();
                            payloadVrstva.Data = new Datagram(Encoding.ASCII.GetBytes("hello world"));

                            //send something like wing mark for recognizing it on server side
                            //SettextBoxDebug(String.Format("{0}\n", packet.ToString()));

                            //sending rest of message
                            for (int i = 0; i < Secret.Length;) //because firts two letters are already used
                            {
                                ipv4Vrstva.TypeOfService = Convert.ToByte(Secret[i++]); //STEGO
                                ipv4Vrstva.Identification = Convert.ToUInt16(Secret[i++]);
                                tcpVrstva.ControlBits = TcpControlBits.None;
                                //tcpVrstva.SequenceNumber = should be changed after 2 min of transferring

                                //sending part            
                                builder = new PacketBuilder(ethernetVrstva, ipv4Vrstva, tcpVrstva, payloadVrstva/*httpVrstva*/); //probably not nesseary, editing original allowed, but just for sure
                                packet = builder.Build(DateTime.Now);
                                communicator.SendPacket(packet);
                                stegosent.Add(packet);

                            }

                            //isSomethingToSay = false;
                            //Secret = ""; //no resend
                            SettextBoxDebug("Everything sended throught ISN + IPID fields\n");
                        }
                        else if (String.Equals(StegoMethod, Lib.listOfStegoMethods[4])) //DNS
                        {
                            if(Secret.Length == 0)
                            {
                                SettextBoxDebug("Message is zero lenght");
                                break;
                            }

                            foreach (char c in Secret)
                            {
                                EthernetLayer ethernetLayer = new EthernetLayer
                            {
                                Source = MacAddressSource,
                                Destination = MacAddressDestination,
                                EtherType = EthernetType.None, // Will be filled automatically.
                            };

                            IpV4Layer ipV4Layer = new IpV4Layer
                            {
                                Source = new IpV4Address(SourceIP),
                                CurrentDestination = new IpV4Address(DestinationIP),
                                Fragmentation = IpV4Fragmentation.None,
                                HeaderChecksum = null, // Will be filled automatically.
                                Identification = 123,
                                Options = IpV4Options.None,
                                Protocol = null, // Will be filled automatically.
                                Ttl = 100,
                                TypeOfService = 0,
                            };

                            UdpLayer udpLayer = new UdpLayer //be aware of filters in server!
                            {
                                SourcePort = SourcePort,
                                DestinationPort = 53, //for this port
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
                                          new DnsQueryResourceRecord(new DnsDomainName("vsb.cz"), DnsType.A, DnsClass.Internet),
                                },
                                Answers = null,
                                Authorities = null,
                                Additionals = null,
                                DomainNameCompressionMode = DnsDomainNameCompressionMode.All,
                            };

                            PacketBuilder builder = new PacketBuilder(ethernetLayer, ipV4Layer, udpLayer, dnsLayer);
                            Packet packet = builder.Build(DateTime.Now);


                        }
                        else
                        {
                            SettextBoxDebug("Nothing happened\n");
                        }
                    }
                }
                else
                {
                    SettextBoxDebug("Nothing to say, we are going to sleep until recheck\n\n");
                    System.Threading.Thread.Sleep(10000);
                    isSomethingToSay = true;
                }
            }
            while (!terminate);
        }

        public void SettextBoxDebug(string text)
        {
            mv.Invoke((MethodInvoker)delegate
            {
                mv.textBoxDebug.Text = text + "\r\n" + mv.textBoxDebug.Text; // runs on UI thread
            });

            //reason: Operace mezi vlákny není platná: Přístup k ovládacímu prvku textBoxDebug proběhl z jiného vlákna než z vlákna, v rámci kterého byl vytvořen.
        }

        public void Terminate()
        {
            this.terminate = true;
        }


    }
}
