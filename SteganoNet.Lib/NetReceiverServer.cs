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
using PcapDotNet.Packets.Http;

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
        public ushort PortLocalDns = 53; //where to expect "fake" DNS service
        public ushort PortLocalHttp = 80; //where to expect "fake" HTTP service
        public ushort PortRemote { get; set; } //used mostly for reply
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
        private bool IsEnstablishedTCP { get; set; }


        public NetReceiverServer(string ipLocalListening, ushort portLocal, string ipRemoteString = "0.0.0.0", ushort portRemote = 0)
        {
            //network ctor
            this.IpLocalListening = new IpV4Address(ipLocalListening);
            this.IpRemoteSpeaker = new IpV4Address(ipRemoteString);
            this.PortLocal = portLocal;
            this.PortRemote = portRemote;
            this.MacAddressLocal = NetStandard.GetMacAddressFromArp(IpLocalListening);
            this.MacAddressRemote = NetStandard.GetMacAddressFromArp(IpRemoteSpeaker); //use gateway mac

            //local running mode
            bool remoteIsSameAsLocal = IpLocalListening.ToString().Equals(IpRemoteSpeaker.ToString());
            bool remoteIsZero = IpRemoteSpeaker.ToString().Equals("0.0.0.0");
            IsListenedSameInterface = remoteIsSameAsLocal || remoteIsZero;

            //bussiness ctor
            StegoPackets = new List<Tuple<Packet, List<int>>>(); //maybe outdated
            StegoBinary = new List<StringBuilder>(); //needs to be initialized in case nothing is incomming
            Messages = new Queue<string>();
            IsEnstablishedTCP = false;
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
                AddInfoMessage(String.Format("Server settings: Local: {0}:{1}, Remote: {2}:{3}", IpLocalListening, PortLocal, IpRemoteSpeaker, PortRemote));

                string filter = "";
                if (IsListenedSameInterface)
                {
                    //AddInfoMessage("Used filter for local debugging = listening same device"); //cannot apply filter which cutting off (reply) packets from same interface
                    filter = String.Format("tcp port {0} or icmp or udp port {1} and not src port {2}", PortLocal, PortLocalDns, PortLocalDns);
                }
                else
                {
                    //cut off replies from same interface
                    filter = String.Format("(not src host {0}) and (tcp port {1} or icmp or udp port {2} and not src port {3})", IpLocalListening, PortLocal, PortLocalDns, PortLocalDns);
                }

                try
                {
                    //syntax of filter https://www.winpcap.org/docs/docs_40_2/html/group__language.html
                    communicator.SetFilter(filter); // Compile and set the filter
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
                                    if (FirstRun) //used for separation of streams based on packet size (needs to be done better)
                                    {
                                        PacketSize = packet.Length;
                                        FirstRun = false;
                                    }

                                    ProcessIncomingV4Packet(packet);
                                }
                                //if (packet.IsValid && packet.IpV6 != null)                                
                                break;
                            }
                        default:
                            throw new InvalidOperationException("The result " + result + " should never be reached here");
                    }
                } while (!Terminate);

                AddInfoMessage(String.Format("Message is assembling from {0} packets", StegoPackets.Count));
                return;
            }
        }

        private void ProcessIncomingV4Packet(Packet packet) //keep it light!
        {
            //How it works:
            //parse packet to layers
            //recognize and check method (initialize of connection etc...)
            //call proper parsing method from stego library
            //save stego substring
            //make answer packet and send it if needed
            //when is terminated, run reasembling to message

            AddInfoMessage("received IPv4: " + (packet.Timestamp.ToString("yyyy-MM-dd hh:mm:ss.fff") + " length:" + packet.Length));

            //same lenght is usually same stego stream
            if (PacketSize != packet.Length) //temporary recognizing of different streams
            {
                FirstRun = true;
                StegoBinary.Add(new StringBuilder("spacebetweenstreams")); //storing just binary messages    
            }

            //parsing layers for processing            
            IpV4Datagram ip = packet.Ethernet.IpV4;
            IcmpEchoDatagram icmp = null;
            TcpDatagram tcp = null;
            UdpDatagram udp = null;
            DnsDatagram dns = null;
            HttpDatagram http = null;
            try
            {
                //AddInfoMessage((ip.IsValid) ? "" : "packet invalid"); //TODO more testing
                icmp = (ip.Icmp.IsValid) ? (IcmpEchoDatagram)ip.Icmp : null;
                tcp = (ip.Tcp.IsValid) ? ip.Tcp : null;
                udp = (ip.Udp.IsValid) ? ip.Udp : null;
                dns = (udp.Dns.IsValid) ? udp.Dns : null;
                http = (tcp.Http.IsValid) ? tcp.Http : null;
            }
            catch (Exception ex)
            {
                AddInfoMessage("Packet discarted, " + ex.Message.ToString());
                return;
            }

            //TODO recognize seting connection + ending...
            //NetAuthentication.ChapChallenge(StegoUsedMethodIds.ToString()); //uses list of used IDs as shared secret
            //remember source => Do not run this method for non steganography sources!

            bool addressWasChangedFromDefault = false;
            if (IpRemoteSpeaker.ToString().Equals("0.0.0.0")) //we need address for answers!
            {
                IpRemoteSpeaker = ip.Source;
                addressWasChangedFromDefault = true;
                AddInfoMessage("Reply IP was changed from 0.0.0.0 to " + IpRemoteSpeaker.ToString());
                //TODO do the same with port, when TCP / UDP then important
            }

            StringBuilder messageCollector = new StringBuilder(); //for appending answers


            //IP methods
            List<int> ipSelectionIds = NetSteganography.GetListMethodsId(NetSteganography.IpRangeStart, NetSteganography.IpRangeEnd, NetSteganography.GetListStegoMethodsIdAndKey());
            if (StegoUsedMethodIds.Any(ipSelectionIds.Contains))
            {
                messageCollector.Append(NetSteganography.GetContent3Network(ip, StegoUsedMethodIds, this)); //TODO send ipSelectionIds only, not all
                //SendReplyPacket(null) => pure IP is not responding 
            }


            //ICMP methods
            List<int> icmpSelectionIds = NetSteganography.GetListMethodsId(NetSteganography.IcmpRangeStart, NetSteganography.IcmpRangeEnd, NetSteganography.GetListStegoMethodsIdAndKey());
            if (StegoUsedMethodIds.Any(icmpSelectionIds.Contains))
            {
                messageCollector.Append(NetSteganography.GetContent3Icmp(icmp, StegoUsedMethodIds, this));
                //if EchoRequest not needed because typeof(icmp) == IcmpEchoDatagram
                SendReplyPacket(NetStandard.GetIcmpEchoReplyPacket(MacAddressLocal, MacAddressRemote, IpLocalListening, IpRemoteSpeaker, icmp));
            }


            //ICMP methods when not expected but ICMP received (pure IP stego etc.)
            if (!StegoUsedMethodIds.Any(icmpSelectionIds.Contains) && icmp != null && icmp.GetType() == typeof(IcmpEchoDatagram))
            {
                //making traffic less suspicious by answering to request, when packet is ICMP but not defined as ICMP stego method                            
                SendReplyPacket(NetStandard.GetIcmpEchoReplyPacket(MacAddressLocal, MacAddressRemote, IpLocalListening, IpRemoteSpeaker, icmp));
            }


            //TCP methods
            List<int> tcpSelectionIds = NetSteganography.GetListMethodsId(NetSteganography.TcpRangeStart, NetSteganography.TcpRangeEnd, NetSteganography.GetListStegoMethodsIdAndKey());
            if (StegoUsedMethodIds.Any(tcpSelectionIds.Contains))
            {
                //TODO running alone is not typical without payload layer => usage in HTTP methods
            }


            //DNS methods
            List<int> dnsSelectionIds = NetSteganography.GetListMethodsId(NetSteganography.DnsRangeStart, NetSteganography.DnsRangeEnd, NetSteganography.GetListStegoMethodsIdAndKey());
            if (StegoUsedMethodIds.Any(dnsSelectionIds.Contains))
            {
                messageCollector.Append(NetSteganography.GetContent7Dns(dns, StegoUsedMethodIds, this));
                PortLocal = PortLocalDns; //TODO should test if port "53" is listening + receiving                
                PortRemote = (PortRemote == 0) ? udp.SourcePort : PortRemote; //if local port is not specified, save it from incoming                               
                SendReplyPacket(NetStandard.GetDnsPacket(MacAddressLocal, MacAddressRemote, IpLocalListening, IpRemoteSpeaker, PortLocal, PortRemote, dns));
            }


            //HTTP methods
            List<int> httpSelectionIds = NetSteganography.GetListMethodsId(NetSteganography.HttpRangeStart, NetSteganography.HttpRangeEnd, NetSteganography.GetListStegoMethodsIdAndKey());
            if (StegoUsedMethodIds.Any(httpSelectionIds.Contains))
            {
                //update local TCP values from arriving packet
                SeqNumberRemote = tcp.SequenceNumber;
                AckNumberRemote = tcp.AcknowledgmentNumber;

                if (tcp.ControlBits == TcpControlBits.Synchronize || (tcp.ControlBits == TcpControlBits.Synchronize | tcp.ControlBits == TcpControlBits.Acknowledgment) || tcp.ControlBits == TcpControlBits.Fin || tcp.ControlBits == (TcpControlBits.Fin | TcpControlBits.Acknowledgment))
                {
                    //enstablishing and terminating branch

                    //SYN
                    if (tcp.ControlBits == TcpControlBits.Synchronize && tcp.ControlBits != (TcpControlBits.Synchronize | TcpControlBits.Acknowledgment))
                    {
                        //messageCollector.Append TCP stego
                        //Pickup stego from that packets

                        AddInfoMessage("Replying with TCP SYN/ACK...");

                        SeqNumberLocal = NetStandard.GetSynOrAckRandNumber(); //replace to static number for debug, could be also steganographic
                        SeqNumberLocal = 500; //TODO STEGO
                        AckNumberLocal = SeqNumberRemote + 1;

                        AddInfoMessage(String.Format("SERVER: SYN seq: {0}, ack: {1}, seqr {2}, ackr {3}", SeqNumberLocal, AckNumberLocal, SeqNumberRemote, AckNumberRemote));
                        TcpLayer tcpLayer = NetStandard.GetTcpLayer(tcp.DestinationPort, tcp.SourcePort, SeqNumberLocal, AckNumberLocal, TcpControlBits.Synchronize | TcpControlBits.Acknowledgment);
                        SendReplyPacket(NetStandard.GetTcpReplyPacket(MacAddressLocal, MacAddressRemote, IpLocalListening, IpRemoteSpeaker, tcpLayer));
                    }

                    //SYN ACK
                    if (tcp.ControlBits == (TcpControlBits.Synchronize | TcpControlBits.Acknowledgment) && tcp.ControlBits != (TcpControlBits.Synchronize))
                    {
                        AddInfoMessage("Server should not receive SYN-ACK");
                        return;
                        //NOTE (is valid?) Do not process STEGO from that packets because its duplicite...
                        //SeqNumberLocal = AckNumberLocal; //outgoing
                        //AckNumberLocal = AckNumberRemote + 1; //outgoing
                        //AddInfoMessage(String.Format("SERVER: SYNACK seq: {0}, ack: {1}, seqr {2}, ackr {3}", SeqNumberLocal, AckNumberLocal, SeqNumberRemote, AckNumberRemote));
                        //TcpLayer tcpLayer = NetStandard.GetTcpLayer(tcp.DestinationPort, tcp.SourcePort, SeqNumberLocal, AckNumberLocal, TcpControlBits.Acknowledgment);
                        //SendReplyPacket(NetStandard.GetTcpReplyPacket(MacAddressLocal, MacAddressRemote, IpLocalListening, IpRemoteSpeaker, tcpLayer));
                    }

                    //ACK below...

                    //FIN
                    if (tcp.ControlBits == TcpControlBits.Fin && tcp.ControlBits != (TcpControlBits.Fin | TcpControlBits.Acknowledgment)) //receive FIN or FIN ACK
                    {
                        //TODO
                        /*
                        SeqNumberLocal = AckNumberRemote;
                        AckNumberLocal = SeqNumberRemote + 1;

                        AddInfoMessage(">>Ending TCP connection with FIN ACK");
                        TcpLayer tcLayer = NetStandard.GetTcpLayer(tcp.DestinationPort, tcp.SourcePort, SeqNumberLocal, AckNumberLocal, TcpControlBits.Fin | TcpControlBits.Acknowledgment);
                        SendReplyPacket(NetStandard.GetTcpReplyPacket(MacAddressLocal, MacAddressRemote, IpLocalListening, IpRemoteSpeaker, tcLayer));
                        */
                    }

                    //FIN ACK                    
                    if (tcp.ControlBits == (TcpControlBits.Fin | TcpControlBits.Acknowledgment) && tcp.ControlBits != TcpControlBits.Fin)
                    {
                        AddInfoMessage("Server should not receive FIN-ACK");
                        return;
                    }
                }
                else //ACK, PSH and others...
                {
                    //standard data handling branch
                    AddInfoMessage("Server data handling");

                    if (tcp.Payload.Length == 0) //when is just ACK (from SYN/ACK) - do not reply
                    {
                        AddInfoMessage("Server received empty message when payload expected, waiting for retransmission..."); //do not react = retransmision
                        return;
                    }

                    //solve TCP for ACK of data
                    SeqNumberLocal = AckNumberRemote;
                    AckNumberLocal = (uint)(SeqNumberRemote + tcp.PayloadLength);
                    TcpLayer tcpLayerReply = NetStandard.GetTcpLayer(tcp.DestinationPort, tcp.SourcePort, SeqNumberLocal, AckNumberLocal, TcpControlBits.Acknowledgment);
                    SendReplyPacket(NetStandard.GetTcpReplyPacket(MacAddressLocal, MacAddressRemote, IpLocalListening, IpRemoteSpeaker, tcpLayerReply)); //acking

                    //solve TCP
                    //SeqNumberLocal
                    //AckNumberLocal
                    //The acknowledgment number field is nonzero while the ACK flag is not set
                    TcpLayer tcpLayer = NetStandard.GetTcpLayer(tcp.DestinationPort, tcp.SourcePort, SeqNumberLocal, 0, TcpControlBits.Push);

                    //solve HTTP for reply
                    messageCollector.Append(NetSteganography.GetContent7Http(http, StegoUsedMethodIds, this));
                    PortLocal = PortLocalHttp;
                    PortRemote = (PortRemote == 0) ? tcp.SourcePort : PortRemote; //if local port is not specified, save it from incoming
                    SendReplyPacket(NetStandard.GetHttpPacket(MacAddressLocal, MacAddressRemote, IpLocalListening, IpRemoteSpeaker, PortLocal, PortRemote, tcpLayer, http));
                }
            }


            //more methods
            //...


            //after methods processing
            StegoBinary.Add(messageCollector);

            if (addressWasChangedFromDefault) //returning global IP address to generic when changed
            {
                IpRemoteSpeaker = new IpV4Address("0.0.0.0");
            }

            return;
        }

        public bool ArePrerequisitiesDone()
        {
            //do actual method list contains keys from "database"?
            if (StegoUsedMethodIds.Intersect(NetSteganography.GetListStegoMethodsIdAndKey().Keys).Any() == false)
            {
                AddInfoMessage("Error! Provided keys are not in list of valid keys.");
                return false;
            }

            if (IpLocalListening == null || IpRemoteSpeaker == null)
            {
                AddInfoMessage("Error! IP addresses are wrongly initialized.");
                return false;
            }

            if (IpRemoteSpeaker.ToString().Equals("0.0.0.0"))
            {
                AddInfoMessage("Warning! Server is listening on all interfaces (reply ip address is parsed from arriving packet).");
            }

            //TODO use iplementation from Client...
            //different test, remoteIP and portRemote are not accepted since its not neeeded
            //TODO ip, ports, ...
            //TODO use version from NetSenderClient

            return true;
        }

        public string GetSecretMessage() //public no-references interface...
        {
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
                //if count of non-ascii > wordchar.Count then remove...
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


        public void SendReplyPacket(List<Layer> layers) //send answer just from list of layers, building and forwarning the answer
        {
            if (layers == null) { return; } //extra protection

            if (layers.Count < 3) //TODO should use complex test of content as client method
            {
                AddInfoMessage("Error! Count of layers in reply packet is low! Not sent.");
                return;
            }

            PacketBuilder builder = new PacketBuilder(layers);
            Packet packet = builder.Build(DateTime.Now);

            selectedDevice = NetDevice.GetSelectedDevice(IpLocalListening); //take the selected adapter
            using (PacketCommunicator communicator = selectedDevice.Open(65536, PacketDeviceOpenAttributes.Promiscuous, 1000))
            {
                communicator.SendPacket(packet);

                string nameOflayer = layers.Last().ToString();
                //should somehow inform for which packet is replying... Parse layers and show non L2 nor L3
                AddInfoMessage("Reply datagram sent from server (" + nameOflayer + ").");
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


        public bool AskTermination() //for handling threads synchronization from UI, returns if is terminated or not
        {
            return this.Terminate;
        }
    }
}
