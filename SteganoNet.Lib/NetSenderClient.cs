using System;
using System.Collections.Generic;
using System.Diagnostics;
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
        public volatile bool Terminate = false; //finishing endless speaking
        public List<int> StegoUsedMethodIds { get; set; }
        public string SecretMessage { get; set; }
        public Queue<string> Messages { get; set; } //status and debug info

        //timers public saved to DelayInMs when used                
        public const int delayGeneral = 100; //gap between all packets in miliseconds
        public const int delayIcmp = 500; //gap for ICMP requests (default 1000)
        public const int IpIdentificationChangeSpeedInMs = 10000; //timeout break for ip identification field - RFC value is 120000 ms = 2 mins

        //network public parametres
        public ushort PortRemote { get; set; }
        public ushort PortLocal { get; set; }
        public MacAddress MacAddressLocal { get; set; }
        public MacAddress MacAddressRemote { get; set; }

        //internal properties based on re-typed public
        private PacketDevice selectedDevice = null;
        private IpV4Address IpOfInterface { get; set; } //isolation of referencies
        private IpV4Address IpOfRemoteHost { get; set; } //isolation of referencies
        private List<StringBuilder> StegoBinary { get; set; } //contains steganography strings in binary
        private int DelayInMs { get; set; } //how long to wait between iterations

        //network priovate parametres = methods value keepers 
        private Stopwatch Timer { get; set; } //IP identification timer
        private bool FirstRun { get; set; } //IP identification decision bit
        private ushort IpIdentification { get; set; } //IP identification value field
        private string TCPphrase { get; set; } //keeping current TCP state
        private uint SeqNumberLocal { get; set; } //for TCP requests
        private uint? SeqNumberRemote { get; set; } //for TCP answers
        private uint AckNumberLocal { get; set; } //for TCP requests
        private uint AckNumberRemote { get; set; } //for TCP answers

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
            Timer = new Stopwatch();
            this.FirstRun = true;
            DelayInMs = delayGeneral;
            TCPphrase = "SYN";
            SeqNumberLocal = 65535; //TODO change to constant here and inside GetTcpLayer()
            AckNumberLocal = 65535; //TODO change to constant here and inside GetTcpLayer()
            AddInfoMessage("Client created...");
        }

        public void Speaking() //thread main method
        {
            if (!ArePrerequisitiesDone()) //check values in properties
            {
                AddInfoMessage("Client is not ready to start, check initialization values...");
                AddInfoMessage("Press ESC to exit");
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

                    //IP methods
                    List<int> ipSelectionIds = NetSteganography.GetListMethodsId(NetSteganography.IpRangeStart, NetSteganography.IpRangeEnd, NetSteganography.GetListStegoMethodsIdAndKey()); //selected all existing int ids in range of IP codes
                    if (StegoUsedMethodIds.Any(ipSelectionIds.Contains))
                    {
                        IpV4Layer ipV4Layer = NetStandard.GetIpV4Layer(IpOfInterface, IpOfRemoteHost); //L3                         

                        //handling method IpIdentificationMethod
                        if (Timer.ElapsedMilliseconds > IpIdentificationChangeSpeedInMs)
                        {
                            FirstRun = true;
                            AddInfoMessage("\t>Timer reseted after: " + Timer.ElapsedMilliseconds);
                            Timer.Restart();
                        }
                        if (FirstRun == false && StegoUsedMethodIds.Contains(NetSteganography.IpIdentificationMethod))
                        {
                            ipV4Layer.Identification = IpIdentification; //put there previous identification = do not change until time expire...
                        }

                        //generic for all methods (name "first" run is confusing, used when new IP identification field is inserted)
                        Tuple<IpV4Layer, string> ipStego = NetSteganography.SetContent3Network(ipV4Layer, StegoUsedMethodIds, SecretMessage, this, FirstRun);
                        ipV4Layer = ipStego.Item1; //save layer containing steganography
                        SecretMessage = ipStego.Item2; //save rest of unsended bites

                        //handling method IpIdentificationMethod
                        if (FirstRun && StegoUsedMethodIds.Contains(NetSteganography.IpIdentificationMethod))
                        {
                            Timer.Start(); //for timeout of 303
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
                        DelayInMs = delayGeneral;
                    }
                    else
                    {
                        //if not stego IP selected, add normal IP layer - they need to be in proper order otherwise "Can't determine protocol automatically from next layer because there is no next layer"
                        IpV4Layer ipV4Layer = NetStandard.GetIpV4Layer(IpOfInterface, IpOfRemoteHost); //L3 
                        layers.Add(ipV4Layer);
                        DelayInMs = delayGeneral;
                    }


                    //ICMP methods
                    List<int> icmpSelectionIds = NetSteganography.GetListMethodsId(NetSteganography.IcmpRangeStart, NetSteganography.IcmpRangeEnd, NetSteganography.GetListStegoMethodsIdAndKey());
                    if (StegoUsedMethodIds.Any(icmpSelectionIds.Contains))
                    {
                        IcmpEchoLayer icmpLayer = new IcmpEchoLayer(); //here is problem in creating correct layer because ICMP doesnt have instanstable generic one
                        Tuple<IcmpEchoLayer, string> icmpStego = NetSteganography.SetContent3Icmp(icmpLayer, StegoUsedMethodIds, SecretMessage, this);
                        icmpLayer = icmpStego.Item1; //save layer containing steganography
                        SecretMessage = icmpStego.Item2; //save rest of unsended bites
                        layers.Add(icmpLayer); //mark layer as done
                        DelayInMs = delayIcmp;
                    }

                    //UDP methods - not implemented


                    //TCP methods
                    List<int> tcpSelectionIds = NetSteganography.GetListMethodsId(NetSteganography.TcpRangeStart, NetSteganography.TcpRangeEnd, NetSteganography.GetListStegoMethodsIdAndKey());
                    if (StegoUsedMethodIds.Any(tcpSelectionIds.Contains))
                    {
                        //how to handle multiple answers and changes of data?
                        //this need to receive answers and pass result to stego method...
                        //probably stego method is handling state, client need to handle receiving...
                        //here are needed to keep ack+seq values and handle them... SetContent is just using them...

                        //do LINQ magic
                        //ipV4Layer.Protocol = IpV4Protocol.Tcp; //set ISN

                        //default for rewrite
                        TcpLayer tcpLayer = NetStandard.GetTcpLayer(PortLocal, PortRemote, SeqNumberLocal, AckNumberLocal);

                        //ACK FINACK
                        //FIN ACK
                        //FIN
                        //DATA ACK
                        //DATA                    
                        //ACK SYNACK

                        if(TCPphrase.Equals("ACK"))
                        {
                            tcpLayer.ControlBits = TcpControlBits.Acknowledgment;

                        }

                        if (TCPphrase.Equals("SYN ACK"))
                        {
                            tcpLayer.ControlBits = TcpControlBits.Synchronize | TcpControlBits.Acknowledgment;

                            SeqNumberLocal = AckNumberRemote;
                            AckNumberLocal = (uint)SeqNumberRemote + 1;
                        }


                        if (TCPphrase.Equals("SYN"))
                        {
                            AddInfoMessage("TCP SYN");
                            tcpLayer.ControlBits = TcpControlBits.Synchronize;

                            //Tuple<TcpLayer, string> tcpStego = NetSteganography.SetContent4Tcp(tcpLayer, StegoUsedMethodIds, SecretMessage, this);
                            //tcpLayer = tcpStego.Item1;
                            //SecretMessage = tcpStego.Item2;

                            //get some values from packet
                            AckNumberLocal = SeqNumberLocal + 1; //expected value from oposite side
                            AckNumberRemote = SeqNumberLocal + 1; //because we know it
                        }

                        



                        layers.Add(tcpLayer);
                        DelayInMs = delayGeneral;
                    }

                    //protection if not enought layers
                    if (layers.Count < 3)
                    {
                        //TODO layers need to be correctly ordered! Cannot append L2 to end...

                        if (!layers.OfType<EthernetLayer>().Any()) //if not contains Etherhetnet layer object
                        {
                            AddInfoMessage("Added L2 in last step");
                            layers.Add(NetStandard.GetEthernetLayer(MacAddressLocal, MacAddressRemote)); //L2
                            DelayInMs = delayGeneral;
                        }

                        if (!layers.OfType<IpV4Layer>().Any())
                        {
                            AddInfoMessage("Added L3 IP in last step");
                            IpV4Layer ipV4LayerTMP = NetStandard.GetIpV4Layer(IpOfInterface, IpOfRemoteHost); //L3
                            layers.Add(ipV4LayerTMP);
                            DelayInMs = delayGeneral;
                        }

                        if (!layers.OfType<IcmpEchoLayer>().Any())
                        {
                            AddInfoMessage("Added L3 ICMP in last step");
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

                    if (layers.OfType<TcpLayer>().Any())
                    {
                        //TODO based on phrase use correct TcpControlBits


                        SeqNumberRemote = NetStandard.WaitForTcpAck(communicator, IpOfInterface, IpOfRemoteHost, PortLocal, PortRemote, AckNumberRemote, TcpControlBits.Synchronize | TcpControlBits.Acknowledgment); //in ack is expected value
                        if (SeqNumberRemote == null)
                        {
                            AddInfoMessage("TCP ACK not received!");
                            //TODO set one phrase back (if), fix values (next iteration is retransmission)
                            //TCPphrase = NetStandard.GetTcpPreviousPhrase(TCPphrase);

                            /* TODO REVERSE this (cannot -1)
                             * AckNumberLocal = SeqNumberLocal + 1; //expected value from oposite side
                             * AckNumberRemote = SeqNumberLocal + 1; //because we know it
                             * 
                             * AckNumberLocal = ;
                             * AckNumberRemote = ;
                             */
                            continue;
                        }
                        else
                        {

                        }
                    }
                    else
                    {
                        System.Threading.Thread.Sleep(DelayInMs); //waiting for sending next one for everyone except TCP
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

            try
            {
                selectedDevice = NetDevice.GetSelectedDevice(IpOfInterface); //take the selected adapter
                using (PacketCommunicator communicatorTMP = selectedDevice.Open(65536, PacketDeviceOpenAttributes.Promiscuous, 1000))
                {
                    //try to use provide interface, if IP is not valid then it makes error... 
                }
            }
            catch
            {

                AddInfoMessage("Error! Inserted interface cannot be opened. (check value of " + IpOfInterface + " and run again)");
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
