using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

using System.Runtime.InteropServices; //console
using System.Net.Sockets;
using System.Net;
using System.Threading;

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

namespace RawSocket
{
    public partial class MainWindow : Form
    {
        private Thread serverThread;
        Server listener;

        private bool isServer = true;
        private bool isServerListening = false;

        //public IList<LivePacketDevice> allDevices; //list of network interfaces
        PacketDevice selectedDevice = null; //which device will be used for communication

        


        public delegate void ParameterizedThreadStart(bool isServerListening);
        public MainWindow()
        {
            InitializeComponent();
            InitialProcedure();
        }

        public MainWindow(bool isServer)
        {
            InitializeComponent();
            this.isServer = isServer; //isServer == false then isClient
            InitialProcedure();
        }

        private void InitialProcedure()
        {
            //AllocConsole(); //console window            

            if (isServer) //changing checkboxes
            {
                checkBoxServer.Checked = true;
                checkBoxClient.Checked = false;
            }
            else
            {
                checkBoxServer.Checked = false;
                checkBoxClient.Checked = true;
            }

            checkBoxServer.Checked = isServer;

            //get devices
            
            // TODO pred listening/connect
            //if (allDevices.Count == 0)
            //    textBoxDebug.Text += "No interfaces found! Make sure WinPcap is installed.\n";

            List<String> IPv4addresses = new List<String>();
            //IPv4addresses.Add("127.0.0.1"); //add localhost //DEBUG!

            int i = 0;
            foreach (LivePacketDevice lpd in Lib.allDevices)
            {
                if (lpd.Description != null)
                {
                    textBoxDebug.Text += String.Format("Interface #{0}: {1}\r\n", i, lpd.Description);
                }
                else
                {
                    textBoxDebug.Text += String.Format("Interface: #{0}: {1}\r\n", i, lpd.Name);
                }
                i++;

                foreach (DeviceAddress nonparsed in lpd.Addresses) //try-catch needed?
                {
                    string tmp = nonparsed.ToString();
                    string[] words = tmp.Split(' '); //Address: Internet 192.168.124.1 Netmask: Internet 255.255.255.0 Broadcast: Internet 0.0.0.0


                    if (words[1] == "Internet6")
                    {
                        textBoxDebug.Text += String.Format("IPv6 skipped\r\n");
                    }

                    if (words[1] == "Internet")
                    {
                        IPv4addresses.Add(words[2]);
                        textBoxDebug.Text += String.Format("IPv4 {0}\r\n", IPv4addresses.Last());
                    }
                }
                textBoxDebug.Text += "----------------------------------------\r\n";
            }

            //IP addresses server      
            //comboBoxServerAddress.DataSource = Dns.GetHostEntry(Dns.GetHostName()).AddressList; //pure from system
            BindingSource bs_servers = new BindingSource();
            bs_servers.DataSource = IPv4addresses;
            comboBoxServerAddress.DataSource = bs_servers;
            comboBoxServerAddress.SelectedIndex = 0;

            //IP addresses client
            //comboBoxClientAddress.DataSource = Dns.GetHostEntry(Dns.GetHostName()).AddressList; //pure from system
            BindingSource bs_clients = new BindingSource();
            bs_clients.DataSource = IPv4addresses;
            comboBoxClientAddress.DataSource = bs_clients;
            comboBoxClientAddress.SelectedIndex = 0;

            //TMP TMP until combobox will be able to change and save value!
            textBoxTmpIp.Text = comboBoxClientAddress.SelectedValue.ToString();

            //methods combobox (text is ID for method)
            List<String> methods = new List<String>();
            methods.Add("ICMP payload");
            methods.Add("IPv4 manipulation");
            methods.Add("TCP manipulation");
            BindingSource bs_methods = new BindingSource();
            bs_methods.DataSource = methods;
            comboBoxMethod.DataSource = bs_methods;
            comboBoxMethod.SelectedIndex = 2; //default method manual predefined option


        }

        //console window initialization
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool AllocConsole();

        
        private void buttonListen_Click(object sender, EventArgs e)  //LISTENING method which starting THREAD (server start)
        {
            if (isServerListening == true) //server is already listening DO DISCONNECT
            {
                isServerListening = false;
                buttonListen.Text = "Listen";

                if (serverThread != null)
                {
                    listener.Terminate(); 
                    //BLBE!
                    //serverThread = new Thread(() => Listening(!isServerListening));
                    //serverThread.Start(); //Additional information: Odkaz na objekt není nastaven na instanci objektu.
                }

                //pcap_freealldevs(alldevs); //We don't need any more the device list. Free it
                textBoxServerStatus.Text = "disconnected";
            }
            else //server is NOT connected
            {
                isServerListening = true;
                buttonListen.Text = "Disconnect";
                string address = comboBoxServerAddress.Text;
                listener = new Server(this);
                listener.tmpIp = address;

                serverThread = new Thread(listener.Listening);
                serverThread.Start();

                textBoxServerStatus.Text = "connected";
            }
        }

        private void buttonPlus_Click(object sender, EventArgs e) //one more window with agent
        {
            Form MainWindow2 = new MainWindow(!isServer); //should have constructor with iterating ports
            MainWindow2.Show();
        }

        private void checkBoxServer_CheckedChanged(object sender, EventArgs e) //protection changing server/client button
        {
            if (checkBoxServer.Checked)
            {
                checkBoxClient.Checked = false;
                groupBoxServer.Enabled = true;
                //groupBoxMethod.Enabled = false;
                buttonSteganogr.Enabled = false;
                groupBoxClient.Enabled = false;
            }
            else
            {
                checkBoxClient.Checked = true;
                groupBoxServer.Enabled = false;
                //groupBoxMethod.Enabled = true;
                buttonSteganogr.Enabled = true;
                groupBoxClient.Enabled = true;
            }
        }
        private void checkBoxClient_CheckedChanged(object sender, EventArgs e) //protection changing server/client button
        {
            if (checkBoxClient.Checked)
            {
                checkBoxServer.Checked = false;
                groupBoxServer.Enabled = false;
                //groupBoxMethod.Enabled = true;
                buttonSteganogr.Enabled = true;
                groupBoxClient.Enabled = true;
            }
            else
            {
                checkBoxServer.Checked = true;
                groupBoxServer.Enabled = true;
                //groupBoxMethod.Enabled = false;
                buttonSteganogr.Enabled = false;
                groupBoxClient.Enabled = false;
            }

        }
        private void buttonSteganogr_Click(object sender, EventArgs e)
        {
            string tmpIp = GetSeletedIP(isServer);
            selectedDevice = Lib.allDevices[Lib.getSelectedInterfaceIndex(tmpIp)]; // Take the selected adapter

            //name of the device //size // promiscuous mode // read timeout
            using (PacketCommunicator communicator = selectedDevice.Open(100, PacketDeviceOpenAttributes.Promiscuous, 1000))
            {

                if (String.Equals(comboBoxMethod.Text, "ICMP payload"))
                {

                }
                else if (String.Equals(comboBoxMethod.Text, "IPv4 manipulation"))
                {

                }
                else if (String.Equals(comboBoxMethod.Text, "TCP manipulation"))
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

                    communicator.SendPacket(BuildTcpPacket(textBoxSecret.Text));

                }
                else
                {
                    textBoxSecret.Text = "Nothing happened";
                }
            }
        }






        //service methods:
        private void PacketHandler(Packet packet) // Callback function invoked by Pcap.Net for every incoming packet
        {
            textBoxDebug.Text += String.Format("{0} length: {1}", packet.Timestamp.ToString("yyyy-MM-dd hh:mm:ss.fff"), packet.Length);
        }
        
       
        


        private string GetSeletedIP(bool isServer) //returns string with IP address of server or client
        {
            //missing protection of inicialization

            string selectedInterfaceIPaddress = "";
            //ComboBox combac = comboBoxServerAddress;
            if (isServer)
            {
                //PRO ZAPIS
                /*this.Invoke((MethodInvoker)delegate {
                    comboBoxServerAddress.Text = "1"; // runs on UI thread
                });
                */              
                selectedInterfaceIPaddress = comboBoxServerAddress.SelectedValue.ToString();
            }
            else
            {
                selectedInterfaceIPaddress = comboBoxClientAddress.SelectedValue.ToString(); //Additional information: Cross-thread operation not valid: Control 'comboBoxClientAddress' accessed from a thread other than the thread it was created on.
            }
            return selectedInterfaceIPaddress;
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

        public IpV4Layer BuildipV4Layer() //removed static!
        {
            IpV4Layer IpV4Layer = new IpV4Layer()
            {
                //Source = new IpV4Address("1.2.3.4"),
                Source = new IpV4Address(textBoxTmpIp.Text),
                CurrentDestination = new IpV4Address("11.22.33.44"),
                Fragmentation = IpV4Fragmentation.None,
                HeaderChecksum = null, // Will be filled automatically.
                Identification = 123,
                Options = IpV4Options.None,
                Protocol = IpV4Protocol.Udp,
                Ttl = 100,
                TypeOfService = 0,
            };

            return IpV4Layer;
        }

        public static PayloadLayer BuildpayloadLayer(string payload)
        {
            PayloadLayer payloadLayer = new PayloadLayer
            {
                Data = new Datagram(Encoding.ASCII.GetBytes(payload)),
            };

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

