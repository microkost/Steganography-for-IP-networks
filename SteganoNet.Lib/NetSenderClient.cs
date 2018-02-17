using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PcapDotNet.Core;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.IpV4;

namespace SteganoNetLib
{
    public class NetSenderClient : INetNode
    {
        //steganography parametres
        public List<int> StegoUsedMethodIds { get; set; }
        public string Secret { get; set; }
        public Queue<string> messages { get; set; }

        //network parametres
        public string IpSourceInput { get; set; }
        public string IpDestinationInput { get; set; }
        public ushort PortDestination { get; set; }
        public ushort PortSource { get; set; }
        public MacAddress MacAddressSource { get; set; }
        public MacAddress MacAddressDestination { get; set; }

        //internal 
        private PacketDevice selectedDevice = null;
        //public volatile bool terminate = false; //ends speaking, wrong way, keep it close!        
        private IpV4Address IpOfInterface { get; set; }
        private IpV4Address IpOfRemoteHost { get; set; }
        private List<StringBuilder> StegoBinary { get; set; } //contains steganography strings in binary
        //private List<Tuple<Packet, List<int>>> StegoPackets { get; set; } //contains steganography packets (maybe outdated)


        public NetSenderClient(string ipOfSendingInterface, ushort portSendFrom = 0)
        {
            //network ctor
            this.IpOfInterface = new IpV4Address(ipOfSendingInterface);
            this.PortSource = portSendFrom;
            MacAddressSource = NetStandard.GetMacAddress(IpOfInterface);
            MacAddressDestination = NetStandard.GetMacAddress(new IpV4Address("0.0.0.0")); //use gateway mac

            //bussiness ctor
            //StegoBinary = new List<StringBuilder>(); //needs to be initialized in case nothing is incomming
            messages = new Queue<string>();
            messages.Enqueue("Client created...");
        }

        public void Speaking() //thread main method
        {
            //todo
        }        

    }
}
