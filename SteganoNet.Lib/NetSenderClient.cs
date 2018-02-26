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
        public volatile bool Terminate = false; //ends endless speaking
        public List<int> StegoUsedMethodIds { get; set; }
        public string SecretMessage { get; set; }
        public Queue<string> Messages { get; set; }

        //network parametres
        public string IpLocalString { get; set; } //converted to IpOfInterface in ctor
        public string IpRemoteString { get; set; } //converted to IpOfRemoteHost in ctor
        public ushort PortRemote { get; set; }
        public ushort PortLocal { get; set; }
        public MacAddress MacAddressLocal { get; set; }
        public MacAddress MacAddressRemote { get; set; }

        //internal 
        private PacketDevice selectedDevice = null;
        private IpV4Address IpOfInterface { get; set; } //isolation of referencies
        private IpV4Address IpOfRemoteHost { get; set; } //isolation of referencies
        private List<StringBuilder> StegoBinary { get; set; } //contains steganography strings in binary
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
            AddInfoMessage("Client created...");
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
                    List<Layer> layers = new List<Layer>(); //list of used layers
                    layers.Add(NetStandard.GetEthernetLayer(MacAddressLocal, MacAddressRemote)); //L2

                    //creating implicit layers
                    IpV4Layer ipV4Layer = NetStandard.GetIpV4Layer(IpOfInterface, IpOfRemoteHost);
                    IcmpEchoLayer icmpLayer = new IcmpEchoLayer();

                    //IP methods                    
                    List<int> ipSelectionIds = NetSteganography.GetListMethodsId(NetSteganography.IpRangeStart, NetSteganography.IpRangeEnd, NetSteganography.GetListStegoMethodsIdAndKey()); //selected all existing int ids in range of IP codes
                    if (StegoUsedMethodIds.Any(ipSelectionIds.Contains))
                    {
                        AddInfoMessage("Making IP layer");
                        Tuple<IpV4Layer, string> ipStego = NetSteganography.SetContent3Network(ipV4Layer, ipSelectionIds, SecretMessage, this);
                        ipV4Layer = ipStego.Item1; //save layer containing steganography
                        SecretMessage = ipStego.Item2; //save rest of unsended bites
                        layers.Add(ipV4Layer); //mark layer as done                        
                    }

                    if(layers.Count < 3)
                    {
                        layers.Add(icmpLayer); //TODO make it better!
                    }


                    //build packet and send
                    //TODO implement sending, implement method SetContent3Network

                    PacketBuilder builder = new PacketBuilder(layers);
                    Packet packet = builder.Build(DateTime.Now);
                    communicator.SendPacket(packet);

                    AddInfoMessage(String.Format("{0} bits left to send", SecretMessage.Count()));
                    try
                    {
                        SecretMessage = SecretMessage.Substring(0, SecretMessage.Length - 1);
                    }
                    catch
                    { Terminate = true; }
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

            if(MacAddressLocal.Equals("{00:00:00:00:00:00}") || MacAddressRemote.Equals("{00:00:00:00:00:00}"))
            {
                AddInfoMessage("Warning! Mac addresses contains suscpicious values.");
            }

            if (IpOfRemoteHost == null || IpOfInterface == null)
            {
                AddInfoMessage("Error! IP addresses are not wrongly initialized.");
                return false;
            }

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
