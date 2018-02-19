using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PcapDotNet.Core;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.Icmp;
using PcapDotNet.Packets.IpV4;

namespace SteganoNetLib
{
    public class NetSenderClient : INetNode
    {
        //steganography parametres
        public volatile bool terminate = false; //ends endless speaking
        public List<int> StegoUsedMethodIds { get; set; }
        public string SecretReadable { get; set; }
        public Queue<string> messages { get; set; }

        //network parametres
        public string IpSourceInput { get; set; } //converted to IpOfInterface in ctor
        public string IpDestinationInput { get; set; } //converted to IpOfRemoteHost in ctor
        public ushort PortDestination { get; set; }
        public ushort PortSource { get; set; }
        public MacAddress MacAddressSource { get; set; }
        public MacAddress MacAddressDestination { get; set; }

        //internal 
        private PacketDevice selectedDevice = null;
        private IpV4Address IpOfInterface { get; set; } //isolation of referencies
        private IpV4Address IpOfRemoteHost { get; set; } //isolation of referencies
        private List<StringBuilder> StegoBinary { get; set; } //contains steganography strings in binary
        //private List<Tuple<Packet, List<int>>> StegoPackets { get; set; } //contains steganography packets (maybe outdated)
        private string SecretInBin { get; set; }


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
            AddInfoMessage("Client created...");

            if (SecretReadable != null || SecretReadable.Length != 0)
            {
                SecretInBin = DataOperations.StringASCII2BinaryNumber(SecretReadable); //results tested in ArePrerequisitiesDone()
                //string max lenght: Can go a lot bigger than 100,000,000 characters, instantly given System.OutOfMemoryException at 1,000,000,000 characters.
            }

        }

        public void Speaking() //thread main method
        {
            if (!ArePrerequisitiesDone()) //check values in properties
            {
                AddInfoMessage("Client is not ready to start, check initialization values...");
                return;
            }

            selectedDevice = NetDevice.GetSelectedDevice(IpOfInterface); //take the selected adapter

            using (PacketCommunicator communicator = selectedDevice.Open(65536, PacketDeviceOpenAttributes.Promiscuous, 1000))
            {
                AddInfoMessage(String.Format("Sending prepared on {0} = {1}...", IpOfInterface, selectedDevice.Description));

                do
                {
                    //basic packet
                    EthernetLayer ethernetLayer = NetStandard.GetEthernetLayer(MacAddressSource, MacAddressDestination);
                    IpV4Layer ipV4Layer = NetStandard.GetIpV4Layer(IpOfInterface, IpOfRemoteHost);
                    IcmpEchoLayer icmpLayer = new IcmpEchoLayer();
                    //PacketBuilder builder = new PacketBuilder(ethernetLayer, ipV4Layer, icmpLayer); // Create the builder that will build our packets
                    
                    //IP methods                    
                    List<int> ipSelectionIds = NetSteganography.GetListMethodsId(NetSteganography.IpRangeStart, NetSteganography.IpRangeEnd, NetSteganography.GetListStegoMethodsIdAndKey()); //selected all existing int ids in range of IP codes
                    if (StegoUsedMethodIds.Any(ipSelectionIds.Contains))
                    {
                        AddInfoMessage("Making IP layer");
                        Tuple<IpV4Layer, string> ipStego = NetSteganography.SetContent3Network(ipV4Layer, ipSelectionIds, SecretInBin, this);
                        ipV4Layer = ipStego.Item1; //save layer containing steganography
                        SecretInBin = ipStego.Item2; //save rest of unsended bites                                                                                              
                    }

                    //build packet and send
                    //TODO implement sending, implement method SetContent3Network

                    AddInfoMessage(String.Format("{0} bits left to send", SecretInBin.Count()));
                }
                while (!terminate); // || SecretInBin == 0

            }
        }

        public bool ArePrerequisitiesDone()
        {
            //do actual method list contains keys from "database"?
            if (StegoUsedMethodIds.Intersect(NetSteganography.GetListStegoMethodsIdAndKey().Keys).Any() == false)
            {
                AddInfoMessage("Provided keys are not in list of valid keys");
                return false;
            }

            if (SecretReadable == null || SecretReadable.Length == 0) //when there is no secret to transffer (wrong initialization)
            {
                AddInfoMessage("Secret in readable form is not available, wrong initialization");
                return false;
            }            

            if (SecretInBin == null)
            {
                AddInfoMessage("Secret wasn't properly transfered from readable to binary form");
                return false;
            }

            //TODO ip, ports, ...

            return true;
        }

        internal void AddInfoMessage(string txt) //add something to output from everywhere else...
        {
            this.messages.Enqueue(txt);
            return;
        }

    }
}
