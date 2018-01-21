using System;
using System.Collections.Generic;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Core;

namespace SteganoNetLib
{
    public class NetReceiverServer : INetNode
    {
        public string StegoMethod { get; set; }
        public string Secret { get; set; } //non binary transfered information
        public Queue<string> messages { get; set; } //txt for UI
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
        }
        
        public void Listening() //thread listening method
        {
            //TODO checkSettings() //check values in properties...

            selectedDevice = NetDevice.GetSelectedDevice(IpOfListeningInterface); //take the selected adapter

            using (PacketCommunicator communicator = selectedDevice.Open(65536, PacketDeviceOpenAttributes.Promiscuous, 1000))
            {
                //Parametres: Open the device // portion of the packet to capture // 65536 guarantees that the whole packet will be captured on all the link layers // promiscuous mode // read timeout                
                messages.Enqueue(String.Format("Listening on {0} = {1}...", IpOfListeningInterface, selectedDevice.Description));                
                
                string filter = String.Format("tcp port {0} or icmp or udp port 53 and not src port 53", PortDestination); //be aware of ports when server is replying to request (DNS), filter catch again response => loop
                communicator.SetFilter(filter); // Compile and set the filter //needs try-catch for new or dynamic filter
                                                //Changing process: implement new method and capture traffic through Wireshark, prepare & debug filter then extend local filtering string by new rule
                                                //syntax of filter https://www.winpcap.org/docs/docs_40_2/html/group__language.html

                do // Retrieve the packets
                {
                    PacketCommunicatorReceiveResult result = communicator.ReceivePacket(out Packet packet);

                    if(packet is null) 
                    {
                        //System.Console.WriteLine(" error in received packed (if received).");
                        continue;
                    }

                    switch (result)
                    {
                        case PacketCommunicatorReceiveResult.Timeout: // Timeout elapsed
                                                                      //continue;
                        case PacketCommunicatorReceiveResult.Ok:
                            {                                
                                if (packet.IsValid && packet.IpV4 != null)//only IPv4 (yet?)
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

                //SettextBoxDebug(String.Format("Message is assembling from {0} packets", StegoPackets.Count));
                string secret = GetSecretMessage(StegoPackets); //process result of steganography
                //SettextBoxDebug(String.Format("Secret in this session: {0}\n", secret));
                StegoPackets.Clear();
                
                return;
            }
        }

        private void ProcessIncomingV4Packet(Packet packet) //keep it light!
        {
            messages.Enqueue("\tprocessing...");
            //parse packet to layers
            //recognize and check method (initialize of connection px.)
            //call method from stego library
            //get answer packet and send it NetReply?

            //StegoPackets.Add(new Tuple<Packet, string>(null, "string"));

            //somehow distinguish order of arrival packets (port number rise only?)
            //solve how to work with list of methods... multiple things in one packet List<int> according to GetListOfStegoMethods
            return;
        }
        private string GetSecretMessage(List<Tuple<Packet, string>> MessageIncluded)
        {            
            return "NotImplementedException";
        }

        public string GetSecretMessage()
        {
            return GetSecretMessage(this.StegoPackets);
        }

    }
}
