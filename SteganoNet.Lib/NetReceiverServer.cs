using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Core;

namespace SteganoNetLib
{
    public class NetReceiverServer : INetNode
    {
        public string StegoMethod { get; set; }
        public string Secret { get; set; }
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
            MacAddressDestination = NetStandard.GetMacAddress(new IpV4Address("0.0.0.0")); //should be later changed in case of LAN communication
        }
        
        public void Listening() //thread listening method
        {
            //TODO checkPrerequisites (try-catch)

            selectedDevice = NetDevice.GetSelectedDevice(IpOfListeningInterface); //take the selected adapter

            using (PacketCommunicator communicator = selectedDevice.Open(65536, PacketDeviceOpenAttributes.Promiscuous, 1000))
            {                
                //Parametres: Open the device // portion of the packet to capture // 65536 guarantees that the whole packet will be captured on all the link layers // promiscuous mode // read timeout
                //SettextBoxDebug(String.Format("Listening on {0} {1}...", serverIP, selectedDevice.Description));

                string filter = String.Format("tcp port {0} or icmp or udp port 53 and not src port 53", PortDestination); //be aware of ports when server is replying to request (DNS), filter catch again response => loop
                communicator.SetFilter(filter); // Compile and set the filter //needs try-catch for new or dynamic filter
                //Changing process: implement new method and capture traffic through Wireshark, prepare & debug filter then extend local filtering string by new rule
                //syntax of filter https://www.winpcap.org/docs/docs_40_2/html/group__language.html

                Packet packet; // Retrieve the packets
                do
                {
                    //SettextBoxDebug("Listening...");
                    PacketCommunicatorReceiveResult result = communicator.ReceivePacket(out packet);
                    switch (result)
                    {
                        case PacketCommunicatorReceiveResult.Timeout: // Timeout elapsed
                            //continue;
                        case PacketCommunicatorReceiveResult.Ok:
                            {
                                //SettextBoxDebug(">Processing...");
                                if (packet.IsValid && packet.IpV4 != null) //only IPv4 (yet?)
                                    ProcessIncomingV4Packet(packet);
                                //communicator.ReceivePackets(0, ProcessIncomingV4Packet); //problems with returning from this method
                                break;
                            }
                        default:
                            throw new InvalidOperationException("The result " + result + " should never be reached here");
                    }
                } while (!terminate);

                //SettextBoxDebug(String.Format("Message is assembling from {0} packets", StegoPackets.Count));
                string secret = GetSecretMessage(StegoPackets); //process result of steganography
                //SettextBoxDebug(String.Format("Secret in this session: {0}\n", secret));
                //StegoPackets.Clear();                
                return;
            }
        }

        private void ProcessIncomingV4Packet(Packet packet) //keep it light!
        {
            //parse packet to layers
            //recognize and check method (initialize of connection)
            //call method from stego library
            //get answer packet and send it NetReply?

            return;
        }

        public string GetSecretMessage(List<Tuple<Packet, string>> MessageIncluded)
        {
            return "NotImplementedException";
        }
    }
}
