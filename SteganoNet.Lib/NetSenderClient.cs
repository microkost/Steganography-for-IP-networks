using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using PcapDotNet.Core;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Dns;
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

        //network private parametres = methods value keepers 
        private Stopwatch Timer { get; set; } //IP identification timer
        private bool FirstRun { get; set; } //IP identification decision bit
        private ushort IpIdentification { get; set; } //IP identification value field
        private string TCPphrase { get; set; } //keeping current TCP state
        private uint SeqNumberLocal { get; set; } //for TCP requests
        private uint? SeqNumberRemote { get; set; } //for TCP answers
        private uint AckNumberLocal { get; set; } //for TCP requests
        private uint AckNumberRemote { get; set; } //for TCP answers
        private uint PayloadSizeTCP { get; set; } //for TCP answers
        private bool isEnstablishedTCP { get; set; }
        private bool isTerminatingTCP { get; set; }
        private bool isAckNeededTCP { get; set; }


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
            SeqNumberLocal = 0; //TODO change to constant here and inside GetTcpLayer()
            AckNumberLocal = 0; //TODO change to constant here and inside GetTcpLayer()
            isEnstablishedTCP = false;
            isTerminatingTCP = false;
            isAckNeededTCP = false;
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

                    /*
                    //TCP methods (this block is not adding layer, solving handshake) block at the end is adding TCP
                    List<int> tcpSelectionIds = NetSteganography.GetListMethodsId(NetSteganography.TcpRangeStart, NetSteganography.TcpRangeEnd, NetSteganography.GetListStegoMethodsIdAndKey());
                    Tuple<object, Type> payloadLayerTuple = null; //for calculating size
                    if (StegoUsedMethodIds.Any(tcpSelectionIds.Contains))
                    {
                        //TcpLayer tcpLayer = NetStandard.GetTcpLayer(PortLocal, PortRemote, SeqNumberLocal, AckNumberLocal, TcpControlBits.None); //default for rewrite

                        if (!isEnstablishedTCP)
                        {
                            if (isTerminatingTCP)
                            {
                                //TODO terminate

                                //clean status
                                //isEnstablishedTCP = false;                                
                                //isTerminatingTCP = false;
                            }

                            List<Layer> layersLocalCopy1 = layers; //replace previous layers...
                            List<Layer> layersLocalCopy2 = layers; //replace previous layers...

                            AddInfoMessage("TCP SYN...");
                            SeqNumberLocal = (uint)1000; //STEGO IN                            
                            AckNumberLocal = 0; //STEGO IN
                            SeqNumberRemote = 0; //we dont know
                            AckNumberRemote = SeqNumberLocal + 1; //we dont know
                            AddInfoMessage(String.Format("\tC: SYN seq: {0}, ack: {1}, seqr {2}, ackr {3}", SeqNumberLocal, AckNumberLocal, SeqNumberRemote, AckNumberRemote));
                            TcpLayer tcpLayer = NetStandard.GetTcpLayer(PortLocal, PortRemote, SeqNumberLocal, AckNumberLocal, TcpControlBits.Synchronize);
                            layersLocalCopy1.Add(tcpLayer);
                            SendPacket(layersLocalCopy1);

                            AckNumberLocal = SeqNumberLocal + 1; //expected value from oposite side
                            AckNumberRemote = SeqNumberLocal + 1; //because we know it
                            //HERE
                            //SeqNumberRemote = NetStandard.WaitForTcpAck(communicator, IpOfInterface, IpOfRemoteHost, PortLocal, PortRemote, AckNumberRemote, TcpControlBits.Synchronize | TcpControlBits.Acknowledgment); //in ack is expected value
                            SeqNumberRemote = AckNumberRemote;                            
                            if (SeqNumberRemote == null)
                            {
                                AddInfoMessage("TCP SYN ACK not received!");
                                //TODO retransmission
                                continue;
                            }
                            else
                            {
                                AddInfoMessage("TCP SYN ACK received.");
                            }

                            AddInfoMessage("TCP ACK...");
                            SeqNumberLocal = AckNumberRemote;
                            AckNumberLocal = (uint)SeqNumberRemote + 1;
                            AddInfoMessage(String.Format("\tC: DATA seq: {0}, ack: {1}, seqr {2}, ackr {3}", SeqNumberLocal, AckNumberLocal, SeqNumberRemote, AckNumberRemote));
                            tcpLayer = NetStandard.GetTcpLayer(PortLocal, PortRemote, SeqNumberLocal, AckNumberLocal, TcpControlBits.Acknowledgment);
                            layersLocalCopy2.Add(tcpLayer);
                            SendPacket(layersLocalCopy2);

                            AddInfoMessage("Client: handshake enstablished...");
                            isEnstablishedTCP = true;
                        }
                        else //isEnstablishedTCP
                        {
                            isAckNeededTCP = true;
                            AddInfoMessage("TCP data ongoing...");
                            //layer not added when isEnstablishedTCP

                            //do what you want, payload magic
                            //tcpLayer = NetStandard.GetTcpLayer(PortLocal, PortRemote, SeqNumberLocal, AckNumberLocal, TcpControlBits.Acknowledgment | TcpControlBits.Push | TcpControlBits.Urgent);
                            //payload add
                            //wait for ACK
                            //uint payloadsize = (uint)packet.Ethernet.IpV4.Tcp.PayloadLength; seqNumberLocal += payloadsize; //expected value from oposite sid
                        }
                    }
                    */

                    //DNS methods
                    List<int> dnsSelectionIds = NetSteganography.GetListMethodsId(NetSteganography.DnsRangeStart, NetSteganography.DnsRangeEnd, NetSteganography.GetListStegoMethodsIdAndKey());
                    if (StegoUsedMethodIds.Any(dnsSelectionIds.Contains))
                    {
                        //create own UDP

                        DnsLayer dnsLayer = NetStandard.GetDnsHeaderLayer(0);
                        int usedbits = 16;
                        try
                        {
                            string partOfSecret = SecretMessage.Remove(usedbits, SecretMessage.Length - usedbits);
                            UInt16 value = Convert.ToUInt16(partOfSecret, 2);
                            SecretMessage = SecretMessage.Remove(0, usedbits);
                            dnsLayer = NetStandard.GetDnsHeaderLayer(value);
                            AddInfoMessage("DNS size: " + dnsLayer.Length);
                        }
                        catch
                        {
                            if (SecretMessage.Length != 0)
                            {                                
                                UInt16 value = Convert.ToByte(SecretMessage.PadLeft(usedbits, '0'), 2);
                                dnsLayer = NetStandard.GetDnsHeaderLayer(value);
                                AddInfoMessage("DNS size: " + dnsLayer.Length);                                
                            }                            
                        }
                        
                        //payloadLayerTuple = new Tuple<object, Type>(dnsLayer, typeof(DnsLayer));
                        isAckNeededTCP = true;
                        //skip if TCP (DNS is not!)
                        layers.Add(dnsLayer); 
                    }

                    //HTTP methods
                    //smth                                        

                    //protection methods, if not enought layers from selection
                    if (layers.Count < 3) //TODO RETURN TO 3
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

                        //todo TCP protection?
                    }

                    AddInfoMessage(String.Format("{0} bits left to send, waiting {1} ms for next", SecretMessage.Length, DelayInMs));
                    //TODO Solve isTerminatingTCP
                    if (SecretMessage.Length == 0)
                    {
                        AddInfoMessage(String.Format("All message departured, you can stop the process by pressing ESC")); //TODO it's confusing when is running from GUI
                        Terminate = true;
                    }

                    //TCP methods are used...
                    if (isAckNeededTCP)
                    {   
                        /*
                        if (payloadLayerTuple.Item2 == typeof(DnsLayer))
                        {
                            AddInfoMessage("DNS payload");
                            DnsLayer payload = (DnsLayer)payloadLayerTuple.Item1;

                            uint payloadsize = (uint)payload.Length;
                            SeqNumberLocal += payloadsize; //expected value from oposite side
                            TcpLayer tcpLayer = NetStandard.GetTcpLayer(PortLocal, PortRemote, SeqNumberLocal, AckNumberLocal, TcpControlBits.Acknowledgment | TcpControlBits.Push | TcpControlBits.Urgent);

                            layers.Add(tcpLayer);
                            layers.Add(payload);                            
                        }

                        //if others...

                        SendPacket(layers);
                        AddInfoMessage(">waiting for TCP ACK");
                        //HERE
                        //SeqNumberRemote = NetStandard.WaitForTcpAck(communicator, IpOfInterface, IpOfRemoteHost, PortLocal, PortRemote, SeqNumberLocal); //in ack is expected value
                        SeqNumberRemote = SeqNumberRemote;
                        if (SeqNumberRemote == null)
                        {
                            AddInfoMessage("TCP ACK not received!");
                            //TODO retransmission
                            continue;
                        }
                        else
                        {
                            AddInfoMessage("TCP ACK received.");
                        }
                        */

                    }
                    else
                    {
                        AddInfoMessage("Not TCP methods sending...");
                        //build packet and send
                        PacketBuilder builder = new PacketBuilder(layers);
                        Packet packet = builder.Build(DateTime.Now); //if exception "Can't determine ether type automatically from next layer", you need to put layers to proper order as RM ISO/OSI specifies...
                        communicator.SendPacket(packet);
                    }


                    /*
                    if (layers.OfType<TcpLayer>().Any()) //procedures of TCP states handling after send
                    {
                        uint SeqNumberRemotePrevious = (uint)SeqNumberRemote; //backup in case of null

                        //{ "SYN", "SYN ACK", "ACK SYNACK", "DATA", "DATA ACK", "FIN", "FIN ACK", "ACK FINACK" }

                        if (TCPphrase.Equals("SYN")) //waits
                        {
                            AddInfoMessage(String.Format("\tSYN seq: {0}, ack: {1}, seqr {2}, ackr {3}", SeqNumberLocal, AckNumberLocal, SeqNumberRemote, AckNumberRemote));
                            AddInfoMessage(String.Format("Waiting up to {0} s for TCP ACK, expected {1}", NetStandard.TcpTimeoutInMs / 1000, AckNumberRemote));
                            SeqNumberRemote = NetStandard.WaitForTcpAck(communicator, IpOfInterface, IpOfRemoteHost, PortLocal, PortRemote, AckNumberRemote, TcpControlBits.Synchronize | TcpControlBits.Acknowledgment); //in ack is expected value                            
                        }

                        if (TCPphrase.Equals("SYN ACK"))
                        {
                            AddInfoMessage(String.Format("\tSYN ACK seq: {0}, ack: {1}, seqr {2}, ackr {3} - never shows", SeqNumberLocal, AckNumberLocal, SeqNumberRemote, AckNumberRemote));
                        }

                        if (TCPphrase.Equals("ACK SYNACK"))
                        {
                            AddInfoMessage(String.Format("\tACK SYNACK seq: {0}, ack: {1}, seqr {2}, ackr {3}", SeqNumberLocal, AckNumberLocal, SeqNumberRemote, AckNumberRemote));
                        }

                        if (TCPphrase.Equals("DATA"))
                        {
                            PayloadSizeTCP = (uint)packet.Ethernet.IpV4.Tcp.PayloadLength; //counting size

                            AddInfoMessage(String.Format("\tDATA seq: {0}, ack: {1}, seqr {2}, ackr {3}, pay: {4}", SeqNumberLocal, AckNumberLocal, SeqNumberRemote, AckNumberRemote, PayloadSizeTCP));
                            AddInfoMessage(String.Format("Waiting up to {0} s for TCP ACK", NetStandard.TcpTimeoutInMs / 1000));

                            //SeqNumberRemote = NetStandard.WaitForTcpAck(communicator, IpOfInterface, IpOfRemoteHost, PortLocal, PortRemote, AckNumberRemote, TcpControlBits.Acknowledgment); //in ack is expected value                        
                            SeqNumberRemote = NetStandard.WaitForTcpAck(communicator, IpOfInterface, IpOfRemoteHost, PortLocal, PortRemote, SeqNumberLocal); //in ack is expected value

                        }

                        if (TCPphrase.Equals("DATA ACK"))
                        {
                            AddInfoMessage(String.Format("\tDATA ACK seq: {0}, ack: {1}, seqr {2}, ackr {3} SHOULD NOT BE HERE REPLY", SeqNumberLocal, AckNumberLocal, SeqNumberRemote, AckNumberRemote));
                            //in ack is expected value
                            //SeqNumberRemote = NetStandard.WaitForTcpAck(communicator, IpOfInterface, IpOfRemoteHost, PortLocal, PortRemote, AckNumberRemote, TcpControlBits.Acknowledgment);
                        }

                        if (TCPphrase.Equals("FIN"))
                        {
                            AddInfoMessage(String.Format("\tFIN seq: {0}, ack: {1}, seqr {2}, ackr {3}", SeqNumberLocal, AckNumberLocal, SeqNumberRemote, AckNumberRemote));
                        }

                        if (TCPphrase.Equals("FIN ACK"))
                        {
                            AddInfoMessage(String.Format("\tFIN ACK seq: {0}, ack: {1}, seqr {2}, ackr {3}", SeqNumberLocal, AckNumberLocal, SeqNumberRemote, AckNumberRemote));
                        }

                        if (TCPphrase.Equals("ACK FINACK"))
                        {
                            AddInfoMessage(String.Format("\tACK FINACK seq: {0}, ack: {1}, seqr {2}, ackr {3}", SeqNumberLocal, AckNumberLocal, SeqNumberRemote, AckNumberRemote));
                        }

                        if (SeqNumberRemote == null)
                        {
                            SeqNumberRemote = SeqNumberRemotePrevious;
                            //DO NOT MOVE PHRASE via GetTcpNextPhrase() because retransmission (probably)
                            AddInfoMessage(String.Format("TCP ACK not received! seq: {0}, ack: {1}, seqr {2}, ackr {3}", SeqNumberLocal, AckNumberLocal, SeqNumberRemote, AckNumberRemote));
                        }
                        else //if seq number confirmed or not requested move it to new phrase or stay
                        {
                            TCPphrase = NetStandard.GetTcpNextPhrase(TCPphrase, "c");
                            AddInfoMessage("Changing to phrase " + TCPphrase + "\r\n----");
                        }
                        

                        AddInfoMessage("Current phrase is " + TCPphrase);
                        //TODO should have their own waiting if needed...
                    }
                    else
                    {                    
                        communicator.SendPacket(packet);
                        System.Threading.Thread.Sleep(DelayInMs); //waiting for sending next one for everyone except TCP
                    }
                    */

                    //isTerminatingTCP
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

        public void SendPacket(List<Layer> layers) //send just from list of layers, building and forwarning the answer
        {
            if (layers == null) { return; } //extra protection

            if (layers.Count < 3) //TODO should use complex test of content as client method
            {
                AddInfoMessage("Warning: Count of layers in reply packet is low!");
            }

            //TODO try-catch
            selectedDevice = NetDevice.GetSelectedDevice(IpOfInterface); //take the selected adapter
            using (PacketCommunicator communicator = selectedDevice.Open(65536, PacketDeviceOpenAttributes.Promiscuous, 1000))
            {
                PacketBuilder builder = new PacketBuilder(layers);
                Packet packet = builder.Build(DateTime.Now);
                communicator.SendPacket(packet);
            }
            return;

        }
    }
}
