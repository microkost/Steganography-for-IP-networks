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

namespace SteganoNetLib
{
    public class NetReceiverServer : INetNode
    {
        //public string StegoMethod { get; set; } //reimplement needed
        public List<int> StegoUsedMethodIds { get; set; }
        public string Secret { get; set; } //non binary transfered information //NOT NESSESARY for server
        public Queue<string> messages { get; set; } //txt info for UI pickuped by another thread
        public string IpSourceInput { get; set; }
        public string IpDestinationInput { get; set; }
        public ushort PortSource { get; set; } //PortListening //obviously not used
        public ushort PortDestination { get; set; } //PortOfRemoteHost
        public MacAddress MacAddressSource { get; set; }
        public MacAddress MacAddressDestination { get; set; }

        //internal 
        private PacketDevice selectedDevice = null;
        public volatile bool terminate = false; //ends listening        
        private IpV4Address IpOfListeningInterface { get; set; }
        private IpV4Address IpOfRemoteHost { get; set; }
        private List<StringBuilder> StegoBinary { get; set; } //contains steganography strings in binary
        private List<Tuple<Packet, List<int>>> StegoPackets { get; set; } //contains steganography packets (maybe outdated)


        public NetReceiverServer(string ipOfListeningInterface, ushort portOfListening = 0)
        {
            this.IpOfListeningInterface = new IpV4Address(ipOfListeningInterface);
            this.PortSource = portOfListening;
            MacAddressSource = NetStandard.GetMacAddress(IpOfListeningInterface);
            MacAddressDestination = NetStandard.GetMacAddress(new IpV4Address("0.0.0.0")); //TODO should be later changed in case of LAN communication

            StegoPackets = new List<Tuple<Packet, List<int>>>();
            StegoBinary = new List<StringBuilder>(); //needs to be initialized in case nothing is incomming
            messages = new Queue<string>();
            messages.Enqueue("Server created...");
        }

        public void Listening() //thread listening method
        {
            if (!AreServerPrerequisitiesDone()) //check values in properties //TODO finalize implementation!
            {
                messages.Enqueue("Server is not ready to start, check initialization values...");
                return;
            }

            selectedDevice = NetDevice.GetSelectedDevice(IpOfListeningInterface); //take the selected adapter

            using (PacketCommunicator communicator = selectedDevice.Open(65536, PacketDeviceOpenAttributes.Promiscuous, 1000))
            {
                //Parametres: Open the device // portion of the packet to capture // 65536 guarantees that the whole packet will be captured on all the link layers // promiscuous mode // read timeout                
                messages.Enqueue(String.Format("Listening on {0} = {1}...", IpOfListeningInterface, selectedDevice.Description));

                //string filter = String.Format("tcp port {0} or icmp or udp port 53 and not src port 53", PortDestination); //be aware of ports when server is replying to request (DNS), filter catch again response => loop
                //communicator.SetFilter(filter); // Compile and set the filter //needs try-catch for new or dynamic filter
                //Changing process: implement new method and capture traffic through Wireshark, prepare & debug filter then extend local filtering string by new rule
                //syntax of filter https://www.winpcap.org/docs/docs_40_2/html/group__language.html

                do // Retrieve the packets
                {
                    PacketCommunicatorReceiveResult result = communicator.ReceivePacket(out Packet packet);

                    if (packet is null)
                    {
                        //messages.Enqueue("\terror in received packed (if received).");
                        continue;
                    }

                    switch (result)
                    {
                        case PacketCommunicatorReceiveResult.Timeout: // Timeout elapsed
                            continue;
                        case PacketCommunicatorReceiveResult.Ok:
                            {
                                if (packet.IsValid && packet.IpV4 != null && packet.IpV4.IsValid)
                                {
                                    ProcessIncomingV4Packet(packet); //only IPv4
                                    //communicator.ReceivePackets(0, ProcessIncomingV4Packet); //problems with returning from this method
                                }
                                //if (packet.IsValid && packet.IpV6 != null && packet.IpV6.IsValid)                                
                                break;
                            }
                        default:
                            throw new InvalidOperationException("The result " + result + " should never be reached here");
                    }
                } while (!terminate);

                messages.Enqueue(String.Format("Message is assembling from {0} packets", StegoPackets.Count));
                //messages.Enqueue(String.Format("Secret in this session: {0}\n", GetSecretMessage(StegoPackets))); //result of steganography
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

            messages.Enqueue("received IPv4: " + (packet.Timestamp.ToString("yyyy-MM-dd hh:mm:ss.fff") + " length:" + packet.Length));

            IpV4Datagram ip = packet.Ethernet.IpV4; //validity and not nullable tested in Listening()

            //parsing layers for processing
            IcmpIdentifiedDatagram icmp = (ip.Icmp.IsValid) ? (IcmpIdentifiedDatagram)ip.Icmp : null;
            TcpDatagram tcp = ip.Tcp; //TODO needs try catch solution?
            UdpDatagram udp = ip.Udp;
            DnsDatagram dns = udp.Dns;

            //TODO recognize seting connection + ending...
            NetAuthentication.ChapChallenge(StegoUsedMethodIds.ToString()); //use list of used IDs as secret!
            //remember source! Do not run this method for non steganography sources!

            //switchem protečou všechna ID metod a jeden packet, do kterého se zapíšou odpovědi nebo který se uloží + casy bez breaků...
            //TODO How to handle answers?

            //StegoMethodIds contain numbered list of uncolissioning methods which can be used simultaneously
            List<int> listOfStegoMethodsIds = NetSteganography.GetListOfStegoMethods().Keys.ToList(); //all
            StringBuilder builder = new StringBuilder();

            //IP methods
            List<int> ipSelectionIds = NetSteganography.GetListMethodIds(300, 399, listOfStegoMethodsIds);
            if (StegoUsedMethodIds.Any(ipSelectionIds.Contains))
            {
                messages.Enqueue("IP...");
                builder.Append(NetSteganography.GetContent3Network(ip, StegoUsedMethodIds)); //TODO clever to send ipSelectionIds only
                //pure IP is not responding to requests
                //if added async processing then add in return value also timestamp or smth how to assembly messages back in order!
                //send packet or layer to reply method in NetStandard to reply according to RFC... (should be async?)
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

        public bool AreServerPrerequisitiesDone()
        {
            //do actual method list contains keys from "database"?
            if (StegoUsedMethodIds.Intersect(NetSteganography.GetListOfStegoMethods().Keys).Any() == false)
            {
                return false;
            }

            //ip, ports, ...

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
            return DataOperations.BinaryNumber2stringASCII(sb.ToString());
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

        internal void AddInfoMessage(string txt) //add something to output from everywhere else...
        {
            this.messages.Enqueue(txt);
            return;
        }

    }
}
