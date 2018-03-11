using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using PcapDotNet.Core;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.Icmp;
using PcapDotNet.Packets.IpV4;

namespace SteganoNetLib
{
    public class NetSenderClient : INetNode
    {
        //steganography public parametres
        public volatile bool Terminate = false; //ends endless speaking
        public List<int> StegoUsedMethodIds { get; set; }
        public string SecretMessage { get; set; }
        public Queue<string> Messages { get; set; }

        //network public parametres
        //public string IpLocalString { get; set; } //converted to IpOfInterface in ctor
        //public string IpRemoteString { get; set; } //converted to IpOfRemoteHost in ctor
        public ushort PortRemote { get; set; }
        public ushort PortLocal { get; set; }
        public MacAddress MacAddressLocal { get; set; }
        public MacAddress MacAddressRemote { get; set; }

        //internal 
        private PacketDevice selectedDevice = null;
        private IpV4Address IpOfInterface { get; set; } //isolation of referencies
        private IpV4Address IpOfRemoteHost { get; set; } //isolation of referencies
        private List<StringBuilder> StegoBinary { get; set; } //contains steganography strings in binary
        private int DelayInMs { get; set; } //how long to wait between iterations
        private ushort SequenceNumber { get; set; } //for legacy usage
        private static Random rand = new Random();


        //private List<Tuple<Packet, List<int>>> StegoPackets { get; set; } //contains steganography packets (maybe outdated)        


        public NetSenderClient(string ipOfSendingInterface, ushort portSendFrom, string ipOfReceivingInterface, ushort portSendTo)
        {
            //network ctor
            this.IpOfInterface = new IpV4Address(ipOfSendingInterface);
            this.PortLocal = portSendFrom;
            this.IpOfRemoteHost = new IpV4Address(ipOfReceivingInterface);
            this.PortRemote = portSendTo;
            this.MacAddressLocal = NetStandard.GetMacAddressFromArp(IpOfInterface);
            this.MacAddressRemote = NetStandard.GetMacAddressFromArp(IpOfRemoteHost);

            //bussiness ctor            
            Messages = new Queue<string>();
            DelayInMs = 0;
            SequenceNumber = (ushort)DateTime.Now.Ticks;
            AddInfoMessage("Client created...");
        }

        public void Speaking() //thread main method
        {
            if (!ArePrerequisitiesDone()) //check values in properties
            {
                AddInfoMessage("Client is not ready to start, check initialization values...");
                return;
            }

            SecretMessage = DataOperations.StringASCII2BinaryNumber(SecretMessage); //convert messsage to binary
            selectedDevice = NetDevice.GetSelectedDevice(IpOfInterface); //take the selected adapter

            using (PacketCommunicator communicator = selectedDevice.Open(65536, PacketDeviceOpenAttributes.Promiscuous, 1000))
            {
                AddInfoMessage(String.Format("Sending prepared on {0} = {1}...", IpOfInterface, selectedDevice.Description));

                do
                {
                    //creating implicit layers
                    List<Layer> layers = new List<Layer>(); //list of used layers
                    layers.Add(NetStandard.GetEthernetLayer(MacAddressLocal, MacAddressRemote)); //L2                    
                    IpV4Layer ipV4Layer = NetStandard.GetIpV4Layer(IpOfInterface, IpOfRemoteHost); //L3                    

                    //IP methods
                    List<int> ipSelectionIds = NetSteganography.GetListMethodsId(NetSteganography.IpRangeStart, NetSteganography.IpRangeEnd, NetSteganography.GetListStegoMethodsIdAndKey()); //selected all existing int ids in range of IP codes
                    if (StegoUsedMethodIds.Any(ipSelectionIds.Contains))
                    {
                        //AddInfoMessage("Making IP layer");
                        Tuple<IpV4Layer, string> ipStego = NetSteganography.SetContent3Network(ipV4Layer, StegoUsedMethodIds, SecretMessage, this);
                        ipV4Layer = ipStego.Item1; //save layer containing steganography
                        SecretMessage = ipStego.Item2; //save rest of unsended bites
                        layers.Add(ipV4Layer); //mark layer as done                        
                    }

                    if (layers.Count < 3)
                    {
                        if (!layers.OfType<EthernetLayer>().Any()) //if not contains Etherhetnet layer object
                        {
                            layers.Add(NetStandard.GetEthernetLayer(MacAddressLocal, MacAddressRemote)); //L2
                        }

                        if (!layers.OfType<IpV4Layer>().Any())
                        {
                            IpV4Layer ipV4LayerTMP = NetStandard.GetIpV4Layer(IpOfInterface, IpOfRemoteHost); //L3
                            layers.Add(ipV4LayerTMP);
                        }

                        //TODO some condition? Quite hardcoded solution...
                        IcmpEchoLayer icmpLayer = new IcmpEchoLayer();
                        icmpLayer.SequenceNumber = SequenceNumber++; //legacy sequence number
                        icmpLayer.Identifier = (ushort)rand.Next(0, 65535);
                        layers.Add(icmpLayer);
                        DelayInMs = 1000;
                    }
                    
                    //build packet and send
                    PacketBuilder builder = new PacketBuilder(layers);
                    Packet packet = builder.Build(DateTime.Now);
                    communicator.SendPacket(packet);
                    AddInfoMessage(String.Format("{0} bits left to send, waiting {1} ms for next", SecretMessage.Length, DelayInMs));
                    System.Threading.Thread.Sleep(DelayInMs);

                    if (SecretMessage.Length == 0)
                    {
                        Terminate = true;
                    }

                }
                while (!Terminate || SecretMessage.Length != 0);
            }
        }

        public bool ArePrerequisitiesDone()
        {
            //do actual method list contains keys from "database"?
            if (StegoUsedMethodIds.Intersect(NetSteganography.GetListStegoMethodsIdAndKey().Keys).Any() == false)
            {
                AddInfoMessage("Error! Provided keys are not in list of valid keys.");
                return false;
            }

            if (SecretMessage == null || SecretMessage.Length == 0) //when there is no secret to transffer (wrong initialization)
            {
                AddInfoMessage("Error! Secret is not available, wrong initialization.");
                return false;
            }

            //should test SecretMessage for containing other characters than 0 / 1

            if (MacAddressLocal.Equals("{00:00:00:00:00:00}") || MacAddressRemote.Equals("{00:00:00:00:00:00}"))
            {
                AddInfoMessage("Warning! Mac addresses contains suscpicious values.");
            }

            if (IpOfRemoteHost == null || IpOfInterface == null)
            {
                AddInfoMessage("Error! IP addresses are wrongly initialized.");
                return false;
            }

            /*
            if (IpLocalString.Equals("0.0.0.0") || IpRemoteString.Equals("0.0.0.0"))
            {
                AddInfoMessage("Warning! IP addresses are wrongly initialized to 0.0.0.0");
                //return false;
            }
            */

            if (PortRemote == 0 || PortLocal == 0)
            {
                AddInfoMessage("Warning! Ports are set to 0, network issue expected.");
            }

            return true;
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
