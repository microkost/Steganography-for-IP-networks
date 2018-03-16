using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using PcapDotNet.Core;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.Icmp;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.Transport;

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
        private uint AckNumberLocal { get; set; } //for TCP requests
        private uint AckNumberRemote { get; set; } //for TCP answers
        private uint SeqNumberLocal { get; set; } //for TCP requests
        private uint? SeqNumberRemote { get; set; } //for TCP answers
        private bool FirstRun { get; set; } //IP identification
        private ushort IpIdentification { get; set; } //IP identification stored value

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
            //SequenceNumber = (ushort)DateTime.Now.Ticks;
            this.FirstRun = true;
            AddInfoMessage("Client created...");
        }

        public void Speaking() //thread main method
        {
            if (!ArePrerequisitiesDone()) //check values in properties
            {
                AddInfoMessage("Client is not ready to start, check initialization values...");
                return;
            }

            const int delayIcmp = 500; //DEBUG, originally 1000
            const int delay = 0;

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


                    //IP methods
                    List<int> ipSelectionIds = NetSteganography.GetListMethodsId(NetSteganography.IpRangeStart, NetSteganography.IpRangeEnd, NetSteganography.GetListStegoMethodsIdAndKey()); //selected all existing int ids in range of IP codes
                    if (StegoUsedMethodIds.Any(ipSelectionIds.Contains))
                    {
                        IpV4Layer ipV4Layer = NetStandard.GetIpV4Layer(IpOfInterface, IpOfRemoteHost); //L3                         
                        if (FirstRun == false && StegoUsedMethodIds.Contains(NetSteganography.IpIdentificationMethod))
                        {
                            ipV4Layer.Identification = IpIdentification; //put there previous identification, if there is previous... I will not change if time not expire...
                        }

                        Tuple<IpV4Layer, string> ipStego = NetSteganography.SetContent3Network(ipV4Layer, StegoUsedMethodIds, SecretMessage, this, FirstRun);
                        ipV4Layer = ipStego.Item1; //save layer containing steganography
                        SecretMessage = ipStego.Item2; //save rest of unsended bites

                        if (FirstRun && StegoUsedMethodIds.Contains(NetSteganography.IpIdentificationMethod))
                        {
                            IpIdentification = ipV4Layer.Identification; //save stego info and reuse it for next two mins
                            FirstRun = false;
                        }
                        else
                        {
                            if (IpIdentification != ipV4Layer.Identification && StegoUsedMethodIds.Contains(NetSteganography.IpIdentificationMethod))
                            {
                                IpIdentification = ipV4Layer.Identification; //when timer expire, save new value for next iteration
                            }
                        }

                        layers.Add(ipV4Layer); //mark layer as done     
                        DelayInMs = delay;
                    }
                    else
                    {
                        //if not stego in IP add normal IP layer - they need to be in proper order otherwise "Can't determine protocol automatically from next layer because there is no next layer"
                        IpV4Layer ipV4Layer = NetStandard.GetIpV4Layer(IpOfInterface, IpOfRemoteHost); //L3 
                        layers.Add(ipV4Layer);
                        DelayInMs = delay;
                    }

                    //ICMP methods
                    List<int> icmpSelectionIds = NetSteganography.GetListMethodsId(NetSteganography.IcmpRangeStart, NetSteganography.IcmpRangeEnd, NetSteganography.GetListStegoMethodsIdAndKey());
                    if (StegoUsedMethodIds.Any(icmpSelectionIds.Contains))
                    {
                        //here is problem in creating correct layer because ICMP doesnt have instanstable generic one
                        IcmpEchoLayer icmpLayer = new IcmpEchoLayer();
                        Tuple<IcmpEchoLayer, string> icmpStego = NetSteganography.SetContent3Icmp(icmpLayer, StegoUsedMethodIds, SecretMessage, this);
                        icmpLayer = icmpStego.Item1; //save layer containing steganography
                        SecretMessage = icmpStego.Item2; //save rest of unsended bites
                        layers.Add(icmpLayer); //mark layer as done     
                        DelayInMs = delayIcmp;
                    }

                    //UDP methods

                    //TCP methods
                    List<int> tcpSelectionIds = NetSteganography.GetListMethodsId(NetSteganography.TcpRangeStart, NetSteganography.TcpRangeEnd, NetSteganography.GetListStegoMethodsIdAndKey());
                    if (StegoUsedMethodIds.Any(icmpSelectionIds.Contains))
                    {
                        //how to handle multiple answers and changes of data?
                        //this need to receive answers and pass result to stego method...
                        //probably stego method is handling state, client need to handle receiving...
                        //here are needed to keep ack+seq values and handle them... SetContent is just using them...

                        TcpLayer tcpLayer = NetStandard.GetTcpLayer(PortLocal, PortRemote, SeqNumberLocal, AckNumberLocal, TcpControlBits.Synchronize);
                        Tuple<TcpLayer, string> tcpStego = NetSteganography.SetContent4Tcp(tcpLayer, StegoUsedMethodIds, SecretMessage, this);
                        tcpLayer = tcpStego.Item1;
                        SecretMessage = tcpStego.Item2;
                        layers.Add(tcpLayer);
                        DelayInMs = delay;
                    }


                    //protection if not enought layers
                    if (layers.Count < 3)
                    {
                        if (!layers.OfType<EthernetLayer>().Any()) //if not contains Etherhetnet layer object
                        {
                            layers.Add(NetStandard.GetEthernetLayer(MacAddressLocal, MacAddressRemote)); //L2
                            DelayInMs = delay;
                        }

                        if (!layers.OfType<IpV4Layer>().Any())
                        {
                            IpV4Layer ipV4LayerTMP = NetStandard.GetIpV4Layer(IpOfInterface, IpOfRemoteHost); //L3
                            layers.Add(ipV4LayerTMP);
                            DelayInMs = delay;
                        }

                        if (!layers.OfType<IcmpEchoLayer>().Any())
                        {
                            Tuple<IcmpEchoLayer, string> icmpStegoTMP = NetSteganography.SetContent3Icmp(new IcmpEchoLayer(), new List<int> { NetSteganography.IcmpGenericPing }, SecretMessage, this);
                            layers.Add(icmpStegoTMP.Item1);
                            DelayInMs = delayIcmp;
                        }
                    }

                    AddInfoMessage(String.Format("{0} bits left to send, waiting {1} ms for next", SecretMessage.Length, DelayInMs));
                    if (SecretMessage.Length == 0)
                    {
                        AddInfoMessage(String.Format("All message departured, you can stop the process by pressing ESC")); //TODO it's confusing when is running from GUI
                        Terminate = true;
                    }

                    //build packet and send
                    PacketBuilder builder = new PacketBuilder(layers);
                    Packet packet = builder.Build(DateTime.Now); //if exception "Can't determine ether type automatically from next layer", you need to put layers to proper order as RM ISO/OSI specifies...
                    communicator.SendPacket(packet);
                    System.Threading.Thread.Sleep(DelayInMs);
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
