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
        private IpV4Address IpOfListeningInterface { get; set; }
        private IpV4Address IpOfRemoteHost { get; set; }
        private PacketDevice selectedDevice = null;
        private List<Tuple<Packet, String>> StegoPackets; //contains steganography to process
        public volatile bool terminate = false; //ends listening        


        public NetReceiverServer(string ipOfListeningInterface, ushort portOfListening = 0)
        {
            this.IpOfListeningInterface = new IpV4Address(ipOfListeningInterface);
            this.PortSource = portOfListening;
            MacAddressSource = NetStandard.GetMacAddress(IpOfListeningInterface);
            MacAddressDestination = NetStandard.GetMacAddress(new IpV4Address("0.0.0.0")); //TODO should be later changed in case of LAN communication

            StegoPackets = new List<Tuple<Packet, String>>();
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
                                if (packet.IsValid && packet.IpV4 != null && packet.IpV4.IsValid) //only IPv4
                                //    if (packet.IsValid && packet.IpV4 != null) //only IPv4
                                    {
                                    ProcessIncomingV4Packet(packet);
                                    //communicator.ReceivePackets(0, ProcessIncomingV4Packet); //problems with returning from this method
                                }
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
            //recognize and check method (initialize of connection px.)
            //call method from stego library
            //get answer packet and send it NetReply?
            //somehow distinguish order of arrival packets (port number rise only?)
            //solve how to work with list of methods... multiple things in one packet List<int> according to GetListOfStegoMethods

            messages.Enqueue("received IPv4: " + (packet.Timestamp.ToString("yyyy-MM-dd hh:mm:ss.fff") + " length:" + packet.Length));

            //TODO recognize seting connection! + ending... //rember source... 

            IpV4Datagram ip = packet.Ethernet.IpV4; //validity and not nullable tested in Listening()

            //parsing layers for processing
            IcmpIdentifiedDatagram icmp = (ip.Icmp.IsValid) ? (IcmpIdentifiedDatagram)ip.Icmp : null;
            TcpDatagram tcp = ip.Tcp; //TODO needs try catch solution..?
            UdpDatagram udp = ip.Udp;
            DnsDatagram dns = udp.Dns;

            //TODO switch or not if-else-if-else
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
                builder.Append(NetSteganography.getContent3Network(ip, StegoUsedMethodIds));                
                //if added async processing then add in return value also timestamp or smth how to assembly messages back in order!
                //send packet / layer to reply method in NetStandard to reply according to RFC... (should be async?)
            }

            /*
            //ICMP methods
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

            //
            StegoPackets.Add(new Tuple<Packet, string>(packet, "string"));

            return;
        }

        public bool AreServerPrerequisitiesDone()
        {
            //do actual method list contains keys from database?
            if (StegoUsedMethodIds.Intersect(NetSteganography.GetListOfStegoMethods().Keys).Any() == false)
            {
                return false;
            }

            //ip, ports, ...

            return true;
        }

        private string GetSecretMessage(List<Tuple<Packet, string>> MessageIncluded) //private internal method
        {
            return "NotImplementedException";
        }

        public string GetSecretMessage() //public no-references interface...
        {
            return GetSecretMessage(this.StegoPackets);
        }

        internal void AddInfoMessage(string txt) //add something to output from everywhere else...
        {
            this.messages.Enqueue(txt);
            return;
        }

    }
}
