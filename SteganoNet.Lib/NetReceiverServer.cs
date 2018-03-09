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
        //public string IpLocalString { get; set; }
        //public string IpRemoteString { get; set; }
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
        private int packetSize { get; set; } //recognize change in stream
        private bool firstRun { get; set; }

        public NetReceiverServer(string ipLocalListening, ushort portLocal, string ipRemoteString, ushort portRemote)
        {
            //network ctor
            this.IpLocalListening = new IpV4Address(ipLocalListening);
            this.IpRemoteSpeaker = new IpV4Address(ipRemoteString);
            this.PortLocal = portLocal;
            this.PortRemote = portRemote;
            this.MacAddressLocal = NetStandard.GetMacAddressFromArp(IpLocalListening);
            this.MacAddressRemote = NetStandard.GetMacAddressFromArp(IpRemoteSpeaker); //use gateway mac

            //bussiness ctor
            StegoPackets = new List<Tuple<Packet, List<int>>>(); //maybe outdated
            StegoBinary = new List<StringBuilder>(); //needs to be initialized in case nothing is incomming
            Messages = new Queue<string>();
            Messages.Enqueue("Server created...");
            this.firstRun = true;
        }

        public void Listening() //thread looped method
        {
            if (!ArePrerequisitiesDone()) //check values in properties //TODO finalize implementation!
            {
                Messages.Enqueue("Server is not ready to start, check initialization values...");
                return;
            }

            selectedDevice = NetDevice.GetSelectedDevice(IpLocalListening); //take the selected adapter

            using (PacketCommunicator communicator = selectedDevice.Open(65536, PacketDeviceOpenAttributes.Promiscuous, 1000))
            {
                //Parametres: Open the device // portion of the packet to capture // 65536 guarantees that the whole packet will be captured on all the link layers // promiscuous mode // read timeout                
                Messages.Enqueue(String.Format("Listening on {0} = {1}...", IpLocalListening, selectedDevice.Description));

                //string filter = String.Format("tcp port {0} or icmp or udp port 53 and not src port 53", PortDestination); //be aware of ports when server is replying to request (DNS), filter catch again response => loop
                //communicator.SetFilter(filter); // Compile and set the filter //needs try-catch for new or dynamic filter
                //Changing process: implement new method and capture traffic through Wireshark, prepare & debug filter then extend local filtering string by new rule
                //syntax of filter https://www.winpcap.org/docs/docs_40_2/html/group__language.html

                //TODO convert secret to binary

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
                                if (packet.IsValid && packet.IpV4 != null)
                                {
                                    if(firstRun)
                                    {
                                        packetSize = packet.Length;
                                        firstRun = false;
                                    }
                                    ProcessIncomingV4Packet(packet);
                                    /*
                                    if (packet.IpV4.IsValid)
                                    {
                                        ProcessIncomingV4Packet(packet); //only IPv4
                                                                         //communicator.ReceivePackets(0, ProcessIncomingV4Packet); //problems with returning from this method
                                    }
                                    */
                                }
                                //if (packet.IsValid && packet.IpV6 != null && packet.IpV6.IsValid)                                
                                break;
                            }
                        default:
                            throw new InvalidOperationException("The result " + result + " should never be reached here");
                    }
                } while (!Terminate);

                AddInfoMessage(String.Format("L> Message is assembling from {0} packets", StegoPackets.Count));
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

            //if (!packet.IpV4.IsValid) this condition needed but not working
            //{
            //    AddInfoMessage("packet invalid");
            //    return;
            //}
           
            AddInfoMessage("L> received IPv4: " + (packet.Timestamp.ToString("yyyy-MM-dd hh:mm:ss.fff") + " length:" + packet.Length));
            //same lenght is usually same stego stream
            
            if(packetSize != packet.Length) //temporary recognizing of different streams
            {
                firstRun = true;
                StegoBinary.Add(new StringBuilder("spacebetweenstreams")); //storing just binary messages    
            }

            IpV4Datagram ip = packet.Ethernet.IpV4; //validity and not nullable tested in Listening()

            //parsing layers for processing
            try
            {
                IcmpIdentifiedDatagram icmp = (ip.Icmp.IsValid) ? (IcmpIdentifiedDatagram)ip.Icmp : null;
                TcpDatagram tcp = ip.Tcp;
                UdpDatagram udp = ip.Udp;
                DnsDatagram dns = udp.Dns;
            }
            catch
            {
                AddInfoMessage("L> packet discarted");
                return;
            }

            //TODO recognize seting connection + ending...
            NetAuthentication.ChapChallenge(StegoUsedMethodIds.ToString()); //uses list of used IDs as shared secret
            //remember source! Do not run this method for non steganography sources!

            //switchem protečou všechna ID metod a jeden packet, do kterého se zapíšou odpovědi nebo který se uloží + casy bez breaků...
            //TODO How to handle answers?

            //StegoMethodIds contain numbered list of uncolissioning methods which can be used simultaneously
            //List<int> listOfStegoMethodsIds = NetSteganography.GetListStegoMethodsIdAndKey().Keys.ToList(); //all
            StringBuilder builder = new StringBuilder();

            //IP methods
            List<int> ipSelectionIds = NetSteganography.GetListMethodsId(NetSteganography.IpRangeStart, NetSteganography.IpRangeEnd, NetSteganography.GetListStegoMethodsIdAndKey());
            if (StegoUsedMethodIds.Any(ipSelectionIds.Contains))
            {
                //AddInfoMessage("L> IP...");
                builder.Append(NetSteganography.GetContent3Network(ip, StegoUsedMethodIds, this)); //TODO clever to send ipSelectionIds only
                //send instance ot RS
                //pure IP is not responding to requests
                //if added async processing then add in return value also timestamp or smth how to assembly messages back in order!
                //send packet or layer to reply method in NetStandard to reply according to RFC... (should be async?)
            }

            List<int> icmpSelectionIds = NetSteganography.GetListMethodsId(NetSteganography.IcmpRangeStart, NetSteganography.IcmpRangeEnd, NetSteganography.GetListStegoMethodsIdAndKey());
            if (StegoUsedMethodIds.Any(ipSelectionIds.Contains))
            {
                //ifEchoRequest, send EchoReply back...
            }

            /*
            //ICMP methods //is part of IP, or separate? => replies
            else if (icmp != null && icmp.IsValid && String.Equals(StegoMethod, Lib.listOfStegoMethods[0]))
            {
                //if stego methods starts 3xx

                messages.Enqueue("ICMP...");
            }

            //TCP methods
            else if (tcp != null && tcp.IsValid && String.Equals(StegoMethod, Lib.listOfStegoMethods[1]))
            {
                messages.Enqueue("TCP...");
            }

            //wtf //its IP method...
            else if (ip != null && ip.IsValid && tcp.IsValid && String.Equals(StegoMethod, Lib.listOfStegoMethods[3])) //ISN + IP ID
            {
                messages.Enqueue("ISN+IP...");
                StegoPackets.Add(new Tuple<Packet, String>(packet, StegoMethod));
            }           

            //DNS methods
            else if (dns != null && dns.IsValid && String.Equals(StegoMethod, Lib.listOfStegoMethods[4])) //DNS
            {
                messages.Enqueue("DNS...");
            }
            */


            StegoBinary.Add(builder); //storing just binary messages
            StegoPackets.Add(new Tuple<Packet, List<int>>(packet, StegoUsedMethodIds)); //storing full packet (maybe outdated)

            return;
        }

        public bool ArePrerequisitiesDone()
        {
            //do actual method list contains keys from "database"?
            if (StegoUsedMethodIds.Intersect(NetSteganography.GetListStegoMethodsIdAndKey().Keys).Any() == false)
            {
                return false;
            }

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
            stegoBinary.ForEach(item => sb.Append(item)); //convert many strings to one
                        
            string[] streams = Regex.Split(sb.ToString(), "spacebetweenstreams"); //split separate messages by server string spacebetweenstreams

            sb.Clear(); //reused for output
            foreach (string word in streams)
            {
                string message = DataOperations.BinaryNumber2stringASCII(word);
                AddInfoMessage("Message: " + message);
                sb.Append(message + "\n\r"); //line splitter //TODO CRYPTOGRAPHY IS NOT HANDLING THIS WELL!
            }

            return sb.ToString();
        }

        private string GetSecretMessage(List<Tuple<Packet, List<int>>> MessageIncluded) //private internal method, source list of packets
        {
            if (MessageIncluded.Count == 0) //nothing to show
            {
                return "error: no packets captured => no message contained";
            }

            //if List<int> is same as local
            //call GetSecretMessageBinary(ProcessIncomingV4Packet(MessageIncluded.Item0)).Binary 
            throw new NotImplementedException();

            //return "Not Implemented Exception";
        }

        public void AddInfoMessage(string txt) //add something to output from everywhere else...
        {
            this.Messages.Enqueue(txt);
            return;
        }
        public bool AskTermination()
        {
            return this.Terminate;
        }
    }
}
