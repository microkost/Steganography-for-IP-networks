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
using System.Diagnostics;

namespace SteganoNetLib
{
    public class NetReceiverServer : INetNode
    {
        //steganography parametres
        public volatile bool Terminate = false; //ends listening otherwise endless       
        public List<int> StegoUsedMethodIds { get; set; }
        public Queue<string> Messages { get; set; } //txt info for UI pickuped by another thread
        public int TimeToWaitForWholeMessageInMs { get; set; } //TODOTO timer for killing

        //network parametres
        public ushort PortLocal { get; set; } //portListening
        //public ushort PortLocalDns = 53; //where to expect "fake" DNS service //turned off to support DNS on different ports
        public ushort PortLocalHttp = 80; //where to expect "fake" HTTP service
        public ushort PortRemote { get; set; } //used mostly for reply
        public MacAddress MacAddressLocal { get; set; }
        public MacAddress MacAddressRemote { get; set; }

        //processing constants
        public const string StreamSeparator = "spacebetweenstreams"; //deprecated                
        public const string WordSeparator = "spacebetweenwords"; //used in same metod
        public const string ZeroSeparator = "spacebetweenzeros"; //used in same word, lower priority when processed GetSecretMessage() than WordSeparator

        //internal         
        private PacketDevice selectedDevice = null;
        private IpV4Address IpLocalListening { get; set; }
        private IpV4Address IpRemoteSpeaker { get; set; }
        private List<StringBuilder> StegoBinary { get; set; } //contains steganography strings in binary
        private int PacketSize { get; set; } //recognize change in stream
        private bool FirstRun { get; set; }
        private bool IsListenedSameInterface { get; set; } //if debug mode is running
        private int messageCounter = 0; //just counting processed messages

        private uint AckNumberLocal { get; set; } //for TCP answers
        private uint AckNumberRemote { get; set; } //for TCP answers
        private uint SeqNumberLocal { get; set; } //for TCP answers
        private uint SeqNumberRemote { get; set; } //for TCP answers


        public NetReceiverServer(string ipLocalListening, ushort portLocal, string ipRemoteString = "0.0.0.0", ushort portRemote = 0)
        {
            //network ctor
            this.IpLocalListening = new IpV4Address(ipLocalListening);
            this.IpRemoteSpeaker = new IpV4Address(ipRemoteString);
            this.PortLocal = portLocal;
            this.PortRemote = portRemote;
            this.MacAddressLocal = NetStandard.GetMacAddressFromIp(IpLocalListening); //NetStandard.GetMacAddressFromArp(IpLocalListening);
            this.MacAddressRemote = NetStandard.GetMacAddressFromIp(IpRemoteSpeaker); //NetStandard.GetMacAddressFromArp(IpRemoteSpeaker); //use gateway mac

            //local running mode
            bool remoteIsSameAsLocal = IpLocalListening.ToString().Equals(IpRemoteSpeaker.ToString());
            bool remoteIsZero = IpRemoteSpeaker.ToString().Equals("0.0.0.0");
            IsListenedSameInterface = remoteIsSameAsLocal || remoteIsZero;

            //bussiness ctor
            StegoBinary = new List<StringBuilder>(); //needs to be initialized in case nothing is incomming
            Messages = new Queue<string>();
            Messages.Enqueue("Server created...");
            this.FirstRun = true;
            TimeToWaitForWholeMessageInMs = 0; //if needed different, change after creation...
        }

        public void Listening() //thread looped method
        {
            if (!ArePrerequisitiesDone()) //check values in properties //TODO finalize implementation!
            {
                AddInfoMessage("Server is not ready to start, check initialization values...");
                return;
            }

            selectedDevice = NetDevice.GetSelectedDevice(IpLocalListening); //take the selected adapter           

            AddInfoMessage("Mac address local: " + MacAddressLocal.ToString()); //DEBUG
            AddInfoMessage("Mac address remote: " + MacAddressRemote.ToString()); //DEBUG

            using (PacketCommunicator communicator = selectedDevice.Open(65536, PacketDeviceOpenAttributes.Promiscuous, 1000))
            {
                //Parametres: Open the device // portion of the packet to capture // 65536 guarantees that the whole packet will be captured on all the link layers // promiscuous mode // read timeout                
                AddInfoMessage(String.Format("Listening on {0} = {1}...", IpLocalListening, selectedDevice.Description));
                AddInfoMessage(String.Format("Server settings: Local: {0}:{1}, Remote: {2}:{3}", IpLocalListening, PortLocal, IpRemoteSpeaker, PortRemote));

                string filter = "";
                if (IsListenedSameInterface)
                {
                    AddInfoMessage("Used filter for local debugging = listening same device"); //cannot apply filter which cutting off (reply) packets from same interface                                        
                    filter = String.Format("(tcp port {0} and tcp port {1}) or (icmp[icmptype] != icmp-echoreply) or (udp port {2} and not src port {3}) or ((ip[6:2] > 0) and (not ip[6] = 64))", PortLocal, PortRemote, PortLocal, PortLocal);
                    //filter = String.Format("(tcp port {0} and tcp port {1}) or (icmp[icmptype] != icmp-echoreply) or (udp port {2} and not src port {3}) or ((ip[6:2] > 0) and (not ip[6] = 64))", PortLocal, PortRemote, PortLocalDns, PortLocalDns); //changed DNS to listen on specified ports
                    //condition ((ip[6:2] > 0) and (not ip[6] = 64)) means matching the ip fragments and ip last fragments, source https://www.wains.be/pub/networking/tcpdump_advanced_filters.txt
                }
                else
                {
                    //cut off replies from same interface, localhost debug needs them
                    filter = String.Format("(not src host {0}) and ((tcp port {1} and tcp port {2})or icmp or udp port {3} and not src port {4}) or (icmp[icmptype] != icmp-echoreply) or ((ip[6:2] > 0) and (not ip[6] = 64))", IpLocalListening, PortLocal, PortRemote, PortLocal, PortLocal);
                    //filter = String.Format("(not src host {0}) and ((tcp port {1} and tcp port {2})or icmp or udp port {3} and not src port {4}) or (icmp[icmptype] != icmp-echoreply) or ((ip[6:2] > 0) and (not ip[6] = 64))", IpLocalListening, PortLocal, PortRemote, PortLocalDns, PortLocalDns); //changed DNS to listen on specified ports
                    //this filter is selecting both tcp ports, TODO add to IsListenedSameInterface version?
                }

                try
                {
                    //syntax of filter https://www.winpcap.org/docs/docs_40_2/html/group__language.html
                    communicator.SetFilter(filter); // Compile and set the filter
                }
                catch (Exception e)
                {

                    //Changing process: implement new method and capture traffic through Wireshark, prepare & debug filter then extend local filtering string by new rule
                    AddInfoMessage("Traffic filter was not applied, because it have wrong format." + e.Message);
                }

                Stopwatch timer = new Stopwatch();
                if (TimeToWaitForWholeMessageInMs > 0) //auto end listening only when is configured
                {
                    AddInfoMessage("Server is going to be listening for " + TimeToWaitForWholeMessageInMs / 1000 + "s and then terminates");
                    timer.Start(); //starting immediatelly, not from first packet.
                }

                do // Retrieve the packets
                {
                    if (timer.ElapsedMilliseconds > TimeToWaitForWholeMessageInMs) //autokill timer timer
                    {
                        Terminate = true;
                        AddInfoMessage("Listening terminated because timer " + TimeToWaitForWholeMessageInMs / 1000 + "s expired");
                        timer.Stop();
                    }

                    Packet packet = null;
                    PacketCommunicatorReceiveResult result = new PacketCommunicatorReceiveResult();
                    try
                    {
                        result = communicator.ReceivePacket(out packet);
                    }
                    catch
                    {
                        //fails when network interface fails... //throw new Exception("Network connection error, restart app and keep connection stable.");
                        AddInfoMessage("Packet Communicator failed!"); //will not show since reading from that is ended
                    }

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
                                    if (FirstRun) //used for separation of streams based on packet size (should be done better)
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

                AddInfoMessage(String.Format("Message is assembling from {0} sub messages", StegoBinary.Count));
                //warning: string "Message is assembling from" is used as termination keyword, be carefull when changing...
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

            AddInfoMessage("-S-E-R-V-E-R--------------------------------" + (++messageCounter));
            AddInfoMessage("received IPv4: " + (packet.Timestamp.ToString("hh:mm:ss.fff") + " length:" + packet.Length));

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
                if (tcp != null)
                {
                    http = (tcp.Http.IsValid) ? tcp.Http : null;
                }
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
                //TODO do not support replying modified values on IP layer (send back same DiffServ in 301/302 methods
            }


            //ICMP methods
            List<int> icmpSelectionIds = NetSteganography.GetListMethodsId(NetSteganography.IcmpRangeStart, NetSteganography.IcmpRangeEnd, NetSteganography.GetListStegoMethodsIdAndKey());
            if (StegoUsedMethodIds.Any(icmpSelectionIds.Contains))
            {
                string received = NetSteganography.GetContent3Icmp(icmp, StegoUsedMethodIds, this);
                messageCollector.Append(received);
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
                AddInfoMessage("7DNS: Be patient with terminating (when manually), wait for reply."); //TODO remove?
                messageCollector.Append(NetSteganography.GetContent7Dns(dns, StegoUsedMethodIds, this));
                //PortLocal = PortLocalDns; //TODO should test if port "53" is listening + receiving                
                PortRemote = (PortRemote == 0) ? udp.SourcePort : PortRemote; //if local port is not specified, save it from incoming                               
                SendReplyPacket(NetStandard.GetDnsPacket(MacAddressLocal, MacAddressRemote, IpLocalListening, IpRemoteSpeaker, PortLocal, PortRemote, dns));

            }


            //HTTP methods
            //HTTP methods
            List<int> httpSelectionIds = NetSteganography.GetListMethodsId(NetSteganography.HttpRangeStart, NetSteganography.HttpRangeEnd, NetSteganography.GetListStegoMethodsIdAndKey());
            if (StegoUsedMethodIds.Any(httpSelectionIds.Contains))
            {
                //update local TCP values from arriving packet
                try
                {
                    SeqNumberRemote = tcp.SequenceNumber;
                    AckNumberRemote = tcp.AcknowledgmentNumber;
                }
                catch
                {
                    return; //when is receiving some another traffic from interface...
                }

                if (tcp.ControlBits == TcpControlBits.Synchronize || (tcp.ControlBits == TcpControlBits.Synchronize | tcp.ControlBits == TcpControlBits.Acknowledgment) || tcp.ControlBits == TcpControlBits.Fin || tcp.ControlBits == (TcpControlBits.Fin | TcpControlBits.Acknowledgment))
                {
                    //enstablishing and terminating branch

                    //SYN
                    if (tcp.ControlBits == TcpControlBits.Synchronize && tcp.ControlBits != (TcpControlBits.Synchronize | TcpControlBits.Acknowledgment))
                    {
                        //TODO pickup stego from that TCP packet!!! here AND everywhere else
                        //messageCollector.Append(NetSteganography.GetContent4Network(tcp, StegoUsedMethodIds, this));

                        AddInfoMessage("Replying with TCP SYN/ACK...");
                        SeqNumberLocal = NetStandard.GetSynOrAckRandNumber(); //TODO STEGO in
                        SeqNumberLocal = NetStandard.GetSynOrAckRandNumber(); //TODO STEGO in
                        AckNumberLocal = SeqNumberRemote + 1;

                        AddInfoMessage(String.Format("SERVER: SYN seq: {0}, ack: {1}, seqr {2}, ackr {3}", SeqNumberLocal, AckNumberLocal, SeqNumberRemote, AckNumberRemote));
                        TcpLayer tcpLayer = NetStandard.GetTcpLayer(tcp.DestinationPort, tcp.SourcePort, SeqNumberLocal, AckNumberLocal, TcpControlBits.Synchronize | TcpControlBits.Acknowledgment);
                        SendReplyPacket(NetStandard.GetTcpReplyPacket(MacAddressLocal, MacAddressRemote, IpLocalListening, IpRemoteSpeaker, tcpLayer));

                        //TODO CHECK FIN METHOD, using same
                    }

                    //SYN ACK
                    if (tcp.ControlBits == (TcpControlBits.Synchronize | TcpControlBits.Acknowledgment) && tcp.ControlBits != (TcpControlBits.Synchronize))
                    {
                        AddInfoMessage("Server should not receive SYN-ACK");
                        return;
                    }

                    //ACK below...

                    //FIN
                    if (tcp.ControlBits == TcpControlBits.Fin && tcp.ControlBits != (TcpControlBits.Fin | TcpControlBits.Acknowledgment)) //receive FIN or FIN ACK
                    {
                        //TODO FINISH and test
                        AddInfoMessage("Replying with TCP FIN/ACK...");
                        SeqNumberLocal = AckNumberRemote;
                        AckNumberLocal = SeqNumberRemote + 1;
                        TcpLayer tcLayer = NetStandard.GetTcpLayer(tcp.DestinationPort, tcp.SourcePort, SeqNumberLocal, AckNumberLocal, TcpControlBits.Fin | TcpControlBits.Acknowledgment);
                        SendReplyPacket(NetStandard.GetTcpReplyPacket(MacAddressLocal, MacAddressRemote, IpLocalListening, IpRemoteSpeaker, tcLayer));

                        AddInfoMessage("I am self terminating...");
                        Terminate = true;
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

                    if (tcp.Payload.Length == 0) //when is just ACK (after SYN/ACK)
                    {
                        AddInfoMessage("Server: ACK received");
                        return; //no reaction to that datagram
                    }

                    if (tcp.ControlBits == (TcpControlBits.Push | TcpControlBits.Acknowledgment)) //ACK of received data
                    {
                        AddInfoMessage("Server: PSH received, ACK outgoing...");
                        //This ACK packet is sent by the server solely to acknowledge the data sent by the client while upper layers process the HTTP request.
                        SeqNumberLocal = AckNumberRemote; //the server's sequence number remains                       
                        AckNumberLocal = (uint)(SeqNumberRemote + tcp.PayloadLength); //acknowledgement number has increased by the length of the payload
                        TcpLayer tcpLayerReply = NetStandard.GetTcpLayer(tcp.DestinationPort, tcp.SourcePort, SeqNumberLocal, AckNumberLocal, TcpControlBits.Acknowledgment);
                        SendReplyPacket(NetStandard.GetTcpReplyPacket(MacAddressLocal, MacAddressRemote, IpLocalListening, IpRemoteSpeaker, tcpLayerReply)); //acking                        
                    }

                    //is to fast! Especially when running locally...
                    System.Threading.Thread.Sleep(NetSenderClient.delayHttp / 4);

                    //solve TCP for DATA push (actual reply to http request)
                    SeqNumberLocal = AckNumberRemote;
                    AckNumberLocal = (uint)(SeqNumberRemote + tcp.PayloadLength);
                    TcpLayer tcpLayer = NetStandard.GetTcpLayer(tcp.DestinationPort, tcp.SourcePort, SeqNumberLocal, AckNumberLocal, (TcpControlBits.Push | TcpControlBits.Acknowledgment));

                    //solve HTTP for reply
                    messageCollector.Append(NetSteganography.GetContent7Http(http, StegoUsedMethodIds, this));
                    PortLocal = PortLocalHttp;
                    PortRemote = (PortRemote == 0) ? tcp.SourcePort : PortRemote; //if local port is not specified, save it from incoming
                    SendReplyPacket(NetStandard.GetHttpPacket(MacAddressLocal, MacAddressRemote, IpLocalListening, IpRemoteSpeaker, PortLocal, PortRemote, tcpLayer, http));
                }
            }


            //more methods


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
            //TODO ip, ports, ... (remoteIP and portRemote are not accepted since its not neeeded)
            //TODO use version from NetSenderClient

            return true;
        }

        public string GetSecretMessage() //public no-references interface...
        {
            return GetSecretMessage(this.StegoBinary);
        }

        private string GetSecretMessage(List<StringBuilder> stegoBinary) //converts list of binaries to messages and make test
        {
            if (stegoBinary.Count == 0) //nothing to show
            {
                return "Error! No packets captured => no message contained";
            }

            if (stegoBinary.Count > 65535) //if message is too big for some reason...
            {
                return "Error! Received too many messages for processing! ";
            }

            //should I firts do 

            //process output to prepare for rest
            List<string> stegoBinaryClean = new List<string>();
            foreach (StringBuilder block in StegoBinary)
            {
                if (block.Length > 1 && !block.Equals(StreamSeparator)) //everything what is not null and separator
                {
                    if (block.ToString().Contains(WordSeparator) || block.ToString().Contains(ZeroSeparator)) //splitting words from same method, should be padded when they were last
                    {
                        string[] metwords = Regex.Split(block.ToString(), WordSeparator); //get strings before and after that separator
                        foreach (string metWord in metwords)
                        {
                            if (metWord.Length == 0)
                            {
                                continue; //do not process empty messages from end
                            }

                            if (metWord.Contains(ZeroSeparator)) //splitting single zeros when they came together in same metod
                            {
                                string[] words = Regex.Split(metWord, ZeroSeparator); //get strings before and after that separator
                                foreach (string singleWord in words)
                                {
                                    if (singleWord.Length != 0) //when its not empty string
                                    {
                                        stegoBinaryClean.Add(singleWord); //add it!
                                    }
                                }
                            }
                            else
                            {
                                stegoBinaryClean.Add(metWord); //add when not ZeroSeparator
                            }
                        }
                    }
                    else
                    {
                        stegoBinaryClean.Add(block.ToString()); //add if not WordSeparator
                    }
                }
                //others are thrown away...
            }

            //clean from starting zeros of every message
            for (int i = 0; i < stegoBinaryClean.Count(); i++)
            {
                string wordToCut = stegoBinaryClean[i].ToString(); //save as string
                while (wordToCut.Length > 1 && wordToCut[0].Equals('0')) //cut intro zeros (when more than 1 char) from string - padding effect, no zeros at the start
                {
                    wordToCut = wordToCut.Remove(0, 1); //cut first zero
                }
                stegoBinaryClean[i] = (wordToCut.Length > 0) ? wordToCut : "0"; //save it back
            }


            StringBuilder sbSingle = new StringBuilder(); //convets every word to ASCII and appending
            StringBuilder sbBinary = new StringBuilder(); //convers whole binary to ASCII

            stegoBinaryClean.ForEach(item => sbSingle.Append(item)); //convert many binary substrings to one message            
            string[] streams = Regex.Split(sbSingle.ToString(), StreamSeparator); //split separate messages by server string spacebetweenstreams //its deprecated...
            sbSingle.Clear(); //reused for output            
            foreach (string word in streams)
            {
                if (word.Length < 8 && !word.Equals("0")) //cut off mess (one char have 8 bits)
                {
                    continue; //making mess when 0 messages
                }

                //two methods of proceesing...              
                sbBinary.Append(word); //all messages are part of one binary                
                sbSingle.Append(DataOperations.BinaryNumber2stringASCII(word)); //each message is separate
            }
            Console.WriteLine("\n"); //just to make it visible in console                       

            string messageFromSingle = sbSingle.ToString();
            string messageFromBinary = DataOperations.BinaryNumber2stringASCII(sbBinary.ToString()).Trim();

            //consistency check https://en.wikipedia.org/wiki/Error_detection_and_correction
            string messageSingleChecked = DataOperations.ErrorDetectionASCII2Clean(messageFromSingle);
            string messageBinaryChecked = DataOperations.ErrorDetectionASCII2Clean(messageFromBinary);

            try //DEBUG printing to file
            {
                //string report = String.Format("Server binary \r\n{0}\r\nSingle \r\n{1}\r\nSingleChecked \r\n{2}\r\nBinaryChecked \r\n{3}\r\n", sbBinary.ToString(), sbSingle.ToString(), (messageSingleChecked ?? "NULL").ToString(), (messageBinaryChecked ?? "NULL").ToString());
                //string FilePath = System.AppDomain.CurrentDomain.BaseDirectory + DateTime.Now.ToLongTimeString() + "-server-secret.txt";
                //System.IO.File.AppendAllText(FilePath, report);
            }
            catch { } //no report

            //decisions which one is correct to return
            if (messageBinaryChecked == null && messageSingleChecked != null) //one is not null
            {
                AddInfoMessage(messageSingleChecked);
                return messageSingleChecked;
            }

            if (messageBinaryChecked != null && messageSingleChecked == null) //one is not null
            {
                AddInfoMessage(messageBinaryChecked);
                return messageBinaryChecked;
            }

            if (messageBinaryChecked == null && messageSingleChecked == null) //both of them are null
            {
                return ("Warning! Following messages are probably corrupted.\n\r" +
                    messageFromSingle + " or " + DataOperations.ErrorDetectionCutHashOut(messageFromSingle) + "\n\r" +
                    messageFromBinary + " or " + DataOperations.ErrorDetectionCutHashOut(messageFromBinary));
            }

            if (messageBinaryChecked != null && messageSingleChecked != null) //none of them are null
            {
                if (messageSingleChecked.Equals(messageBinaryChecked)) //when they are same
                {
                    AddInfoMessage(messageBinaryChecked);
                    return messageBinaryChecked; //it does not matter                    
                }
                else
                {
                    Console.WriteLine("\tWarning: Message and check messages are not same after assembling!");
                    if (messageBinaryChecked.Length > messageFromSingle.Length) //return longer one
                    {
                        AddInfoMessage(messageBinaryChecked);
                        return messageBinaryChecked;
                    }
                    else
                    {
                        AddInfoMessage(messageFromSingle);
                        return messageFromSingle;
                    }
                }
            }

            return ("Warning! Following messages are corrupted.\n\r" +
                    "\t" + messageFromSingle + " or " + DataOperations.ErrorDetectionCutHashOut(messageFromSingle) + "\n\r" +
                    "\t" + messageFromBinary + " or " + DataOperations.ErrorDetectionCutHashOut(messageFromBinary));
        }

        public void SendReplyPacket(List<Layer> layers) //send answer just from list of layers, building and forwarning the answer
        {
            if (layers == null) { return; }

            if (layers.Count < 3) //TODO should use complex test of content as client method
            {
                AddInfoMessage("Error! Count of layers in reply packet is low! Not sent.");
                return;
            }

            selectedDevice = NetDevice.GetSelectedDevice(IpLocalListening); //take the selected adapter
            using (PacketCommunicator communicator = selectedDevice.Open(65536, PacketDeviceOpenAttributes.Promiscuous, 1000))
            {
                PacketBuilder builder = new PacketBuilder(layers);
                Packet packet = builder.Build(DateTime.Now);
                communicator.SendPacket(packet);
                AddInfoMessage("Reply datagram sent from server (" + layers.Last().ToString() + ").");
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

        public void SetTermination() //used in for terminating based on output delivered to use
        {
            this.Terminate = true;
        }
    }
}
