using System;
using System.Collections.Generic;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Core;
using PcapDotNet.Packets.Icmp;
using PcapDotNet.Packets.Transport;
using PcapDotNet.Packets.Dns;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace SteganoNetLib
{
    public class NetReceiverServer : INetNode
    {
        //steganography parametres
        public volatile bool Terminate = false; //ends listening        
        public List<int> StegoUsedMethodIds { get; set; }
        public Queue<string> Messages { get; set; } //txt info for UI pickuped by another thread

        //network parametres
        public ushort PortLocal { get; set; } //PortListening //obviously not used
        public ushort PortRemote { get; set; } //PortOfRemoteHost
        public MacAddress MacAddressLocal { get; set; }
        public MacAddress MacAddressRemote { get; set; }

        //internal         
        private PacketDevice selectedDevice = null;
        private IpV4Address IpLocalListening { get; set; }
        private IpV4Address IpRemoteSpeaker { get; set; }
        private List<StringBuilder> StegoBinary { get; set; } //contains steganography strings in binary
        private List<Tuple<Packet, List<int>>> StegoPackets { get; set; } //contains steganography packets (maybe outdated)    
        private int PacketSize { get; set; } //recognize change in stream
        private bool FirstRun { get; set; }
        private bool IsListenedSameInterface { get; set; } //if debug mode is running

        private uint AckNumberLocal { get; set; } //for TCP answers
        private uint AckNumberRemote { get; set; } //for TCP answers
        private uint SeqNumberLocal { get; set; } //for TCP answers
        private uint SeqNumberRemote { get; set; } //for TCP answers
        private uint? SeqNumberBase { get; set; } //for TCP answers
        private uint AckNumberBase { get; set; } //for TCP answers


        public NetReceiverServer(string ipLocalListening, ushort portLocal, string ipRemoteString = "0.0.0.0", ushort portRemote = 0)
        {
            //network ctor
            this.IpLocalListening = new IpV4Address(ipLocalListening);
            this.IpRemoteSpeaker = new IpV4Address(ipRemoteString);
            this.PortLocal = portLocal;
            this.PortRemote = portRemote;
            this.MacAddressLocal = NetStandard.GetMacAddressFromArp(IpLocalListening);
            this.MacAddressRemote = NetStandard.GetMacAddressFromArp(IpRemoteSpeaker); //use gateway mac
            IsListenedSameInterface = (IpLocalListening.Equals(IpRemoteSpeaker)) ? true : false; //local debug mode?

            //bussiness ctor
            StegoPackets = new List<Tuple<Packet, List<int>>>(); //maybe outdated
            StegoBinary = new List<StringBuilder>(); //needs to be initialized in case nothing is incomming
            Messages = new Queue<string>();
            Messages.Enqueue("Server created...");
            this.FirstRun = true;
        }

        public void Listening() //thread looped method
        {
            if (!ArePrerequisitiesDone()) //check values in properties //TODO finalize implementation!
            {
                AddInfoMessage("Server is not ready to start, check initialization values...");
                return;
            }

            selectedDevice = NetDevice.GetSelectedDevice(IpLocalListening); //take the selected adapter           

            using (PacketCommunicator communicator = selectedDevice.Open(65536, PacketDeviceOpenAttributes.Promiscuous, 1000))
            {
                //Parametres: Open the device // portion of the packet to capture // 65536 guarantees that the whole packet will be captured on all the link layers // promiscuous mode // read timeout                
                AddInfoMessage(String.Format("Listening on {0} = {1}...", IpLocalListening, selectedDevice.Description));

                string filter = "";
                if (IsListenedSameInterface)
                {
                    AddInfoMessage("Debug: listening same device"); //cannot apply filter which cutting off (reply) packets from same interface
                    filter = String.Format("tcp port {0} or icmp or udp port 53 and not src port 53", PortLocal);
                }
                else
                {
                    //cut off replies from same interface
                    filter = String.Format("(not src host {0}) and (tcp port {1} or icmp or udp port 53 and not src port 53)", IpLocalListening, PortLocal);
                }

                try
                {
                    //syntax of filter https://www.winpcap.org/docs/docs_40_2/html/group__language.html
                    communicator.SetFilter(filter); // Compile and set the filter
                    AddInfoMessage("Traffic filter applied successfully");
                }
                catch
                {
                    //Changing process: implement new method and capture traffic through Wireshark, prepare & debug filter then extend local filtering string by new rule
                    AddInfoMessage("Traffic filter was not applied, because it have wrong format.");
                }

                do // Retrieve the packets
                {
                    PacketCommunicatorReceiveResult result = communicator.ReceivePacket(out Packet packet);

                    if (packet is null)
                    {
                        continue;
                    }

                    switch (result)
                    {
                        case PacketCommunicatorReceiveResult.Timeout: // Timeout elapsed
                            continue;
                        case PacketCommunicatorReceiveResult.Ok:
                            {
                                if (packet.IsValid && packet.IpV4 != null) //only IPv4
                                {
                                    if (FirstRun) //used for separation of streams based on packet size
                                    {
                                        PacketSize = packet.Length;
                                        FirstRun = false;
                                    }

                                    ProcessIncomingV4Packet(packet);
                                    //communicator.ReceivePackets(0, ProcessIncomingV4Packet); //problems with returning from this method

                                }
                                //if (packet.IsValid && packet.IpV6 != null)                                
                                break;
                            }
                        default:
                            throw new InvalidOperationException("The result " + result + " should never be reached here");
                    }
                } while (!Terminate);

                AddInfoMessage(String.Format("Message is assembling from {0} packets", StegoPackets.Count));
                //AddInfoMessagee(String.Format("Secret in this session: {0}\n", GetSecretMessage(StegoPackets))); //result of steganography
                //StegoPackets.Clear();                
                return;
            }
        }

        private void ProcessIncomingV4Packet(Packet packet) //keep it light!
        {
            //parse packet to layers
            //recognize and check method (initialize of connection etc...)
            //call proper parsing method from stego library
            //get answer packet and send it

            AddInfoMessage("received IPv4: " + (packet.Timestamp.ToString("yyyy-MM-dd hh:mm:ss.fff") + " length:" + packet.Length));

            //same lenght is usually same stego stream
            if (PacketSize != packet.Length) //temporary recognizing of different streams
            {
                FirstRun = true;
                StegoBinary.Add(new StringBuilder("spacebetweenstreams")); //storing just binary messages    
            }

            //parsing layers for processing            
            IpV4Datagram ip = packet.Ethernet.IpV4; //TODO add test
            IcmpEchoDatagram icmp = null;
            TcpDatagram tcp = null;
            UdpDatagram udp = null;
            DnsDatagram dns = null;
            try
            {
                //AddInfoMessage((ip.IsValid) ? "" : "L> packet invalid"); //TODO more testing
                icmp = (ip.Icmp.IsValid) ? (IcmpEchoDatagram)ip.Icmp : null;
                tcp = (ip.Tcp.IsValid) ? ip.Tcp : null;
                udp = (ip.Udp.IsValid) ? ip.Udp : null;
                dns = (udp.Dns.IsValid) ? udp.Dns : null;
            }
            catch (Exception ex)
            {
                AddInfoMessage("Packet discarted, " + ex.Message.ToString());
                return;
            }

            //TODO recognize seting connection + ending...
            NetAuthentication.ChapChallenge(StegoUsedMethodIds.ToString()); //uses list of used IDs as shared secret
                                                                            //remember source => Do not run this method for non steganography sources!

            StringBuilder messageCollector = new StringBuilder(); //for appending answers

            //IP methods
            List<int> ipSelectionIds = NetSteganography.GetListMethodsId(NetSteganography.IpRangeStart, NetSteganography.IpRangeEnd, NetSteganography.GetListStegoMethodsIdAndKey());
            if (StegoUsedMethodIds.Any(ipSelectionIds.Contains))
            {
                messageCollector.Append(NetSteganography.GetContent3Network(ip, StegoUsedMethodIds, this)); //TODO send ipSelectionIds only, not all
                //SendReplyPacket(null) => pure IP is not responding 
                //TODO if ever added async processing then save also timestamp for assembling messages back in order!
            }

            //ICMP methods
            List<int> icmpSelectionIds = NetSteganography.GetListMethodsId(NetSteganography.IcmpRangeStart, NetSteganography.IcmpRangeEnd, NetSteganography.GetListStegoMethodsIdAndKey());
            if (StegoUsedMethodIds.Any(icmpSelectionIds.Contains))
            {
                messageCollector.Append(NetSteganography.GetContent3Icmp(icmp, StegoUsedMethodIds, this));
                //if EchoRequest then...
                SendReplyPacket(NetStandard.GetIcmpEchoReplyPacket(MacAddressLocal, MacAddressRemote, IpLocalListening, IpRemoteSpeaker, icmp));
            }

            //ICMP methods when not expected but ICMP received (pure IP stego etc.)
            if (!StegoUsedMethodIds.Any(icmpSelectionIds.Contains) && icmp != null && icmp.GetType() == typeof(IcmpEchoDatagram))
            {
                //making traffic less suspicious by answering, when is ICMP but not defined as ICMP stego method                            
                SendReplyPacket(NetStandard.GetIcmpEchoReplyPacket(MacAddressLocal, MacAddressRemote, IpLocalListening, IpRemoteSpeaker, icmp));
            }

            /*
            //TCP methods
            List<int> tcpSelectionIds = NetSteganography.GetListMethodsId(NetSteganography.TcpRangeStart, NetSteganography.TcpRangeEnd, NetSteganography.GetListStegoMethodsIdAndKey());
            if (StegoUsedMethodIds.Any(tcpSelectionIds.Contains))
            {
                //REMOTE IS WHAT ARRIVED
                //LOCAL IS WHAT IS OUTGOING

                //receive SYN
                if (tcp.ControlBits == TcpControlBits.Synchronize) 
                {
                    AddInfoMessage("Replying with TCP SYN/ACK...");

                    SeqNumberRemote = tcp.SequenceNumber; //arrived
                    AckNumberRemote = tcp.AcknowledgmentNumber; //not used
                    SeqNumberLocal = 5000; //TODO STEGO
                    AckNumberLocal = SeqNumberRemote + 1;

                    AddInfoMessage(String.Format("SERVER: SYN seq: {0}, ack: {1}, seqr {2}, ackr {3}", SeqNumberLocal, AckNumberLocal, SeqNumberRemote, AckNumberRemote));
                    TcpLayer tcLayer = NetStandard.GetTcpLayer(tcp.DestinationPort, tcp.SourcePort, SeqNumberLocal, AckNumberLocal, TcpControlBits.Synchronize | TcpControlBits.Acknowledgment);
                    SendReplyPacket(NetStandard.GetTcpReplyPacket(MacAddressLocal, MacAddressRemote, IpLocalListening, IpRemoteSpeaker, tcLayer));
                }

                //SYN ACK
                if (tcp.ControlBits == (TcpControlBits.Synchronize | TcpControlBits.Acknowledgment))
                {
                    SeqNumberRemote = AckNumberLocal; //arrived
                    AckNumberRemote = SeqNumberLocal; //arrived
                    SeqNumberLocal = AckNumberLocal; //outgoing
                    AckNumberLocal = AckNumberRemote + 1; //outgoing

                    AddInfoMessage(String.Format("SERVER: SYNACK seq: {0}, ack: {1}, seqr {2}, ackr {3}", SeqNumberLocal, AckNumberLocal, SeqNumberRemote, AckNumberRemote));
                    TcpLayer tcLayer = NetStandard.GetTcpLayer(tcp.DestinationPort, tcp.SourcePort, SeqNumberLocal, AckNumberLocal, TcpControlBits.Acknowledgment);
                    SendReplyPacket(NetStandard.GetTcpReplyPacket(MacAddressLocal, MacAddressRemote, IpLocalListening, IpRemoteSpeaker, tcLayer));
                }

                
                //connection enstablished
                if ((tcp.ControlBits & TcpControlBits.Acknowledgment) > 0) //&& (SeqNumberLocal - SeqNumberBase == 1)) //receive ACK //&& (AckNumberLocal - AckNumberBase == 1)s
                {
                    AddInfoMessage(">>Handshake complete!");
                    //return;
                    //save some values?
                }
                
                
                //receive DATA
                if (tcp.ControlBits == TcpControlBits.Push)
                {
                    AddInfoMessage(">>Data section");
                    SeqNumberLocal = AckNumberRemote;
                    AckNumberLocal = (uint)(SeqNumberRemote + tcp.PayloadLength);
                    //SettextBoxDebug(">>Adding TCP..."); //before first adding check PSH: Push Function
                    //StegoPackets.Add(new Tuple<Packet, String>(packet, StegoMethod));

                    //SettextBoxDebug(">>Replying with ACK...");
                    TcpLayer tcLayer = NetStandard.GetTcpLayer(tcp.DestinationPort, tcp.SourcePort, SeqNumberLocal, AckNumberLocal, TcpControlBits.Acknowledgment);
                    SendReplyPacket(NetStandard.GetTcpReplyPacket(MacAddressLocal, MacAddressRemote, IpLocalListening, IpRemoteSpeaker, tcLayer));
                }

                //terminating connection
                if (tcp.ControlBits == TcpControlBits.Fin || tcp.ControlBits == (TcpControlBits.Fin | TcpControlBits.Acknowledgment)) //receive FIN or FIN ACK
                {
                    SeqNumberLocal = AckNumberRemote;
                    AckNumberLocal = SeqNumberRemote + 1;

                    AddInfoMessage(">>Ending TCP connection with FIN ACK");
                    TcpLayer tcLayer = NetStandard.GetTcpLayer(tcp.DestinationPort, tcp.SourcePort, SeqNumberLocal, AckNumberLocal, TcpControlBits.Fin | TcpControlBits.Acknowledgment);
                    SendReplyPacket(NetStandard.GetTcpReplyPacket(MacAddressLocal, MacAddressRemote, IpLocalListening, IpRemoteSpeaker, tcLayer));

                    //TODO? SEND ALSO FIN ACK
                    //TODO wait for ACK, ideally

                    //SeqNumberBase = null; //reset enstablished connection
                    //leave method
                }
            }
            */


            //DNS methods
            List<int> dnsSelectionIds = NetSteganography.GetListMethodsId(NetSteganography.DnsRangeStart, NetSteganography.DnsRangeEnd, NetSteganography.GetListStegoMethodsIdAndKey());
            if (StegoUsedMethodIds.Any(dnsSelectionIds.Contains))
            {
                messageCollector.Append(NetSteganography.GetContent7Dns(dns, StegoUsedMethodIds, this));
                //TODO should test if port 53 is listening + receiving
                SendReplyPacket(NetStandard.GetDnsPacket(MacAddressLocal, MacAddressRemote, IpLocalListening, IpRemoteSpeaker, 53, PortRemote, dns));

            }            

            StegoBinary.Add(messageCollector); //storing just binary messages
                                               //StegoPackets.Add(new Tuple<Packet, List<int>>(packet, StegoUsedMethodIds)); //storing full packet (maybe outdated)

            return;
        }

        public bool ArePrerequisitiesDone()
        {
            //do actual method list contains keys from "database"?
            if (StegoUsedMethodIds.Intersect(NetSteganography.GetListStegoMethodsIdAndKey().Keys).Any() == false)
            {
                return false;
            }

            //different test, remoteIP and portRemote are not accepted since its not neeeded
            //TODO use iplementation from Client...
            //TODO ip, ports, ...
            //TODO use version from NetSenderClient

            return true;
        }

        public string GetSecretMessage() //public no-references interface...
        {
            //return GetSecretMessage(this.StegoPackets);
            return GetSecretMessage(this.StegoBinary);
        }

        private string GetSecretMessage(List<StringBuilder> stegoBinary) //private internal method, source list of binary strings (lighter)
        {
            if (stegoBinary.Count == 0) //nothing to show
            {
                return "error: no packets captured => no message contained";
            }

            //TODO if (stegoBinary.Count > XXX) //if message is too big

            StringBuilder sb = new StringBuilder();
            stegoBinary.ForEach(item => sb.Append(item)); //convert many binary substrings to one message

            string[] streams = Regex.Split(sb.ToString(), "spacebetweenstreams"); //split separate messages by server string spacebetweenstreams

            sb.Clear(); //reused for output
            foreach (string word in streams)
            {
                if (word.Length < 8) //cut off mess (one char have 8 bits)
                {
                    AddInfoMessage("Info: empty word removed from received messages. ");
                    continue;
                }

                string message = DataOperations.BinaryNumber2stringASCII(word);

                /*
                //foreach message, foreach word
                //count non-ascii... ;
                //if count of non-ascii > word.Count then remove...
                if(DataOperations.IsASCII(message))
                {
                    AddInfoMessage("Info: Non ascii message removed from server");
                    continue;
                } 
                */

                sb.Append(message + "\n\r"); //line splitter //TODO: CRYPTOGRAPHY IS NOT HANDLING THIS WELL!
            }


            //if more than half of next message contains message 
            //parse by "\n\r"
            //cut of empty lines
            //join together longer and ASCII one

            return sb.ToString();
        }

        /*
            public void SendReplyPacket(Packet packet) //universal anwering method
            {
                selectedDevice = NetDevice.GetSelectedDevice(IpLocalListening); //take the selected adapter
                using (PacketCommunicator communicator = selectedDevice.Open(65536, PacketDeviceOpenAttributes.Promiscuous, 1000))
                {
                    communicator.SendPacket(packet);
                }
                return;
            }
            */

        public void SendReplyPacket(List<Layer> layers) //send answer just from list of layers, building and forwarning the answer
        {
            if (layers == null) { return; } //extra protection

            if (layers.Count < 3) //TODO should use complex test of content as client method
            {
                AddInfoMessage("L> Warning: Count of layers in reply packet is low! ");
            }

            PacketBuilder builder = new PacketBuilder(layers);
            Packet packet = builder.Build(DateTime.Now);

            selectedDevice = NetDevice.GetSelectedDevice(IpLocalListening); //take the selected adapter
            using (PacketCommunicator communicator = selectedDevice.Open(65536, PacketDeviceOpenAttributes.Promiscuous, 1000))
            {
                communicator.SendPacket(packet);
            }
            return;

        }

        public void AddInfoMessage(string txt) //add something to output from everywhere else...
        {
            if (txt.Length == 0) //do not show zero lenght message, but sometimes simplifying other tasks.
                return;

            this.Messages.Enqueue(txt);
            return;
        }
        public bool AskTermination() //for handling threads synchronization from UI
        {
            return this.Terminate;
        }
    }
}
