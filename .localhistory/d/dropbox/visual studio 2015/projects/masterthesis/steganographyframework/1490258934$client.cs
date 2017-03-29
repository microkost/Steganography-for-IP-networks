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
using PcapDotNet.Core.Extensions; //getMacAddress!

using System.Windows.Forms;

namespace SteganographyFramework
{
    public class Client
    {
        public volatile bool terminate = false;
        public string StegoMethod { get; set; } //contains name of choosen method
        public string Secret { get; set; } //contains magic to be transferred

        private MainWindow mv; //not good

        //---NETWORKING PARAMETRES---//
        public IpV4Address SourceIP { get; set; }
        public IpV4Address DestinationIP { get; set; }
        public ushort DestinationPort { get; set; }
        public ushort SourcePort { get; set; }
        public MacAddress MacAddressSource { get; set; } = new MacAddress("01:01:01:01:01:01"); //replaced by real after selecting interface
        public MacAddress MacAddressDestination { get; set; } = new MacAddress("02:02:02:02:02:02");

        public Client(MainWindow mv)
        {
            this.mv = mv;
        }
        public void Speaking()
        {
            int selectedInterface = Lib.getSelectedInterfaceIndex(SourceIP); //get index
            MacAddressSource = Lib.allDevices[selectedInterface].GetMacAddress(); //get real MAC address of outbound interface
            MacAddressDestination = NetworkMethods.getDestinationMacAddress(DestinationIP); //get real destination mac based on arp request

            if (Secret == null) //when there is no secret to transffer (wrong initialization)
                return;

            do //to controll thread until terminate is true
            {
                using (PacketCommunicator communicator = Lib.allDevices[selectedInterface].Open(100, PacketDeviceOpenAttributes.Promiscuous, 1000)) //name of the device //size // promiscuous mode // read timeout
                {

                    if (Secret.Length == 0)
                    {
                        SettextBoxDebug("Message has zero lenght");
                        break;
                    }

                    SettextBoxDebug(String.Format("Processing of method {0} started", StegoMethod));
                    if (String.Equals(StegoMethod, Lib.listOfStegoMethods[0])) //ICMP
                    {
                        EthernetLayer ethernetLayer = NetworkMethods.GetEthernetLayer(MacAddressSource, MacAddressDestination); //2 Ethernet Layer                        
                        IpV4Layer ipV4Layer = NetworkMethods.GetIpV4Layer(SourceIP, DestinationIP); //3 IPv4 Layer                             
                        IcmpEchoLayer icmpLayer = new IcmpEchoLayer(); //4 ICMP Layer                        

                        PacketBuilder builder = new PacketBuilder(ethernetLayer, ipV4Layer, icmpLayer); // Create the builder that will build our packets

                        //send start sequence
                        for (int i = 0; i < Secret.Length;)
                        {

                            //In each ICMP packet 4 bytes of hidden data can be inserted. The hidden data will be placed in both Identifier (2 bytes) and Sequence number (2 bytes) fields. 
                            try
                            {
                                icmpLayer.Identifier = (ushort)Secret[i++];
                            }
                            catch
                            {
                                //in case that there are no more letters in string secret
                            }

                            try
                            {
                                icmpLayer.SequenceNumber = (ushort)Secret[i++];
                            }
                            catch
                            {
                                //in case that there are no more letters in string secret
                            }

                            Packet packet = builder.Build(DateTime.Now); // Rebuild the packet
                            communicator.SendPacket(packet); // Send down the packet                            
                            System.Threading.Thread.Sleep(1000); //wait 1s for sending next one to simulate real network
                        }

                        //send end sequence

                        terminate = true;


                    }
                    else if (String.Equals(StegoMethod, Lib.listOfStegoMethods[1])) //TCP
                    {
                        List<Packet> stegosent = new List<Packet>(); //debug only

                        //2
                        EthernetLayer ethernetLayer = NetworkMethods.GetEthernetLayer(MacAddressSource, MacAddressDestination);

                        //3
                        IpV4Layer ipv4Vrstva = NetworkMethods.GetIpV4Layer(SourceIP, DestinationIP);
                        ipv4Vrstva.TypeOfService = Convert.ToByte(0); //STEGO ready //0 default value
                        ipv4Vrstva.Source = SourceIP;
                        ipv4Vrstva.CurrentDestination = DestinationIP; //ipv4Vrstva.Destination is read only
                        ipv4Vrstva.Fragmentation = IpV4Fragmentation.None;
                        ipv4Vrstva.HeaderChecksum = null; //Will be filled automatically.
                        ipv4Vrstva.Identification = 555; //STEGO
                        ipv4Vrstva.Options = IpV4Options.None;
                        ipv4Vrstva.Protocol = IpV4Protocol.Tcp; //set ISN
                        ipv4Vrstva.Ttl = 128;

                        //4
                        TcpLayer tcpLayer = new TcpLayer //= BuildTcpLayer();
                        {
                            SourcePort = (ushort)SourcePort,
                            DestinationPort = (ushort)DestinationPort,
                            SequenceNumber = 2017,
                            ControlBits = TcpControlBits.Synchronize, //WHEN ACK as first then making troubles!                                
                        };

                        PacketBuilder builder = new PacketBuilder(ethernetLayer, ipv4Vrstva, tcpLayer);

                        char[] secretmessage = Secret.ToCharArray();
                        foreach (char c in secretmessage)
                        {
                            ipv4Vrstva.TypeOfService = Convert.ToByte((int)c); //TODO some extra protection
                            Packet packet = builder.Build(DateTime.Now);
                            stegosent.Add(packet);
                        }

                        foreach (Packet p in stegosent)
                        {
                            communicator.SendPacket(p);
                            System.Threading.Thread.Sleep(200);
                        }

                        //SettextBoxDebug(String.Format("Sent {0}", Lib.listOfStegoMethods[1].ToString()));
                        terminate = true;
                    }
                    else if (String.Equals(StegoMethod, Lib.listOfStegoMethods[2])) //IP
                    {
                        SettextBoxDebug("IP not implemented\n");
                        terminate = true;

                        // Set IPv4 parameters
                        //sipV4Layer.Identification = (ushort)i;
                    }
                    else if (String.Equals(StegoMethod, Lib.listOfStegoMethods[3])) //ISN + IP ID
                    {
                        List<Packet> stegosent = new List<Packet>(); //debug only

                        //nessesary to do TCP handshake
                        //SYN paket obsahuje prázdný TCP segment a má nastavený příznak SYN v TCP hlavičce.                            

                        // Ethernet Layer
                        EthernetLayer ethernetVrstva = NetworkMethods.GetEthernetLayer(MacAddressSource, MacAddressDestination);

                        // IPv4 Layer
                        IpV4Layer ipv4Vrstva = NetworkMethods.GetIpV4Layer(SourceIP, DestinationIP);
                        ipv4Vrstva.TypeOfService = Convert.ToByte(0); //STEGO ready //0 default value
                        ipv4Vrstva.Identification = 555; //STEGO                        

                        //needs to be finalize? ipv4Vrstva.Finalize();

                        // TCPv4 Layer
                        TcpLayer tcpVrstva = GetTcpLayer(TcpControlBits.Synchronize);
                        tcpVrstva.SequenceNumber = Convert.ToUInt32(Secret[1]); //STEGO
                        tcpVrstva.AcknowledgmentNumber = 0; //Expert Info (Warn/Protocol): Acknowledgment number: Broken TCP. The acknowledge field is nonzero while the ACK flag is not set

                        //what about payload?
                        PayloadLayer payloadVrstva = new PayloadLayer();
                        payloadVrstva.Data = new Datagram(Encoding.ASCII.GetBytes("Just casual payload"));

                        PacketBuilder builder = new PacketBuilder(ethernetVrstva, ipv4Vrstva, tcpVrstva, payloadVrstva); // Create the builder that will build our packets, build the packet, send the packet
                        Packet packet = builder.Build(DateTime.Now);
                        communicator.SendPacket(packet);
                        stegosent.Add(packet);

                        //send something like wing mark for recognizing it on server side

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
                        terminate = true;
                    }
                    else if (String.Equals(StegoMethod, Lib.listOfStegoMethods[4])) //DNS
                    {
                        List<Packet> stegosent = new List<Packet>(); //debug only

                        EthernetLayer ethernetLayer = NetworkMethods.GetEthernetLayer(MacAddressSource, MacAddressDestination);
                        IpV4Layer ipV4Layer = NetworkMethods.GetIpV4Layer(SourceIP, DestinationIP);
                        UdpLayer udpLayer = NetworkMethods.GetUdpLayer(SourcePort, 53);

                        List<String> domainsToAsk = new List<string>() { "vsb.cz", "seznam.cz", "google.com", "yahoo.com", "github.com", "uwasa.fi", "microsoft.com", "yr.no", "googlecast.com" }; //used as infinite loop
                        int indexindomains = 0;

                        foreach (char c in Secret)
                        {
                            if (indexindomains == domainsToAsk.Count())
                                indexindomains = 0;

                            DnsLayer dnsLayer = NetworkMethods.GetDnsHeaderLayer((ushort)c); //total capacity 16 bit, idea to make a XOR
                            dnsLayer.IsResponse = false;
                            dnsLayer.Queries = new List<DnsQueryResourceRecord>() { NetworkMethods.GetDnsQuery(domainsToAsk[indexindomains++]) }; //ndex was out of range. Must be non-negative and less than the size of the collection.

                            PacketBuilder builder = new PacketBuilder(ethernetLayer, ipV4Layer, udpLayer, dnsLayer);
                            Packet packet = builder.Build(DateTime.Now);
                            communicator.SendPacket(packet);
                            System.Threading.Thread.Sleep(900); //wait 1s for sending next one to simulate real network                        
                        }

                        terminate = true;

                    }
                    else
                    {
                        SettextBoxDebug("Nothing happened\n");
                    }
                    SettextBoxDebug(String.Format("Processing of method {0} finished\n", StegoMethod));
                }

                /*
                 if(isSomethingToSay)
                 {
                    //whole code
                 }
                else
                {
                    SettextBoxDebug("Nothing to say, we are going to sleep until recheck\n\n");
                    System.Threading.Thread.Sleep(10000);
                    isSomethingToSay = true;
                }
                */
            }
            while (!terminate);
        }

        public void SettextBoxDebug(string text)
        {
            try
            {
                mv.Invoke((MethodInvoker)delegate //An unhandled exception: Cannot access a disposed object when closing app
                {
                    mv.textBoxDebug.Text = text + "\r\n" + mv.textBoxDebug.Text; // runs on UI thread
                });
            }
            catch
            {
                SettextBoxDebug("Printing failed at client location => dont close it when is still listening"); //temporary solution
                mv.Close();
            }
        }

        public void Terminate()
        {
            this.terminate = true;
        }


        public TcpLayer GetTcpLayer(TcpControlBits SetBits = TcpControlBits.Synchronize) //default SYN
        {
            TcpLayer tcpVrstva = new TcpLayer();
            tcpVrstva.SourcePort = SourcePort;
            tcpVrstva.DestinationPort = DestinationPort;
            tcpVrstva.SequenceNumber = Convert.ToUInt32(1); //Implement naturally!
            tcpVrstva.AcknowledgmentNumber = 50;
            tcpVrstva.ControlBits = SetBits; //needs to be changed regarding flow of TCP!
            tcpVrstva.Window = 100;
            tcpVrstva.Checksum = null; //Will be filled automatically
            tcpVrstva.UrgentPointer = 0;
            tcpVrstva.Options = TcpOptions.None;
            return tcpVrstva;
        }

    }

}
