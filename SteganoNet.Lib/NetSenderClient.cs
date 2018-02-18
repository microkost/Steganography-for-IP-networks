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
        public volatile bool terminate = false; //ends endless speaking
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
            if (!AreServerPrerequisitiesDone()) //check values in properties
            {
                messages.Enqueue("Client is not ready to start, check initialization values...");
                return;
            }

            selectedDevice = NetDevice.GetSelectedDevice(IpOfInterface); //take the selected adapter

            using (PacketCommunicator communicator = selectedDevice.Open(65536, PacketDeviceOpenAttributes.Promiscuous, 1000))
            {
                messages.Enqueue(String.Format("Sending prepared on {0} = {1}...", IpOfInterface, selectedDevice.Description));

                do // Retrieve the packets
                {
                    //get layers //edit content //based on MethodsIds
                }
                while (!terminate);

            }
        }

        public bool AreServerPrerequisitiesDone()
        {
            //do actual method list contains keys from "database"?
            if (StegoUsedMethodIds.Intersect(NetSteganography.GetListOfStegoMethods().Keys).Any() == false)
                return false;

            if (Secret == null) //when there is no secret to transffer (wrong initialization)
                return false;

            if (Secret.Length == 0) //message to transfer has zero lenght
                return false;

            //TODO ip, ports, ...

            return true;
        }
    }
}
