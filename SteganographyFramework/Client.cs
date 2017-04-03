using PcapDotNet.Core;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using PcapDotNet.Base;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Dns;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.Icmp;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.Transport;
using PcapDotNet.Core.Extensions; //getMacAddress!

using System.Windows.Forms;
using System.Diagnostics;

namespace SteganographyFramework
{
    public class Client
    {
        public volatile bool terminate = false;
        public string StegoMethod { get; set; } //contains name of choosen method
        public string Secret { get; set; } //contains magic to be transferred

        private MainWindow mv; //not good

        //---NETWORKING PARAMETRES---//
        public IpV4Address SourceIP { get; set; }
        public IpV4Address DestinationIP { get; set; }
        public ushort DestinationPort { get; set; }
        public ushort SourcePort { get; set; }
        public MacAddress MacAddressSource { get; set; } = new MacAddress("01:01:01:01:01:01"); //replaced by real MAC after selecting interface
        public MacAddress MacAddressDestination { get; set; } = new MacAddress("02:02:02:02:02:02"); //replaced by ARP request later
        private uint ackNumberLocal { get; set; } //for TCP requests
        private uint ackNumberRemote { get; set; } //for TCP answers
        private uint seqNumberLocal { get; set; } //for TCP requests
        private uint? seqNumberRemote { get; set; } //for TCP answers

        public Client(MainWindow mv)
        {
            this.mv = mv;
        }
        public void Speaking()
        {
            int selectedInterface = Lib.getSelectedInterfaceIndex(SourceIP); //get index
            MacAddressSource = Lib.allDevices[selectedInterface].GetMacAddress(); //get real MAC address of outbound interface
            MacAddressDestination = NetworkMethods.getDestinationMacAddress(DestinationIP); //get real destination mac based on arp request

            if (Secret == null) //when there is no secret to transffer (wrong initialization)
                return;

            do //to controll thread until terminate is true
            {

                using (PacketCommunicator communicator = Lib.allDevices[selectedInterface].Open(100, PacketDeviceOpenAttributes.Promiscuous, 1000)) //name of the device //size // promiscuous mode // read timeout
                {
                    if (Secret.Length == 0)
                    {
                        SettextBoxDebug("Message to transfer has zero lenght");
                        break;
                    }

                    SettextBoxDebug(String.Format("Processing of method {0} started", StegoMethod));
                    if (String.Equals(StegoMethod, Lib.listOfStegoMethods[0])) //ICMP
                    {
                        List<string> blockOfSecret = new List<string>(); //debug only

                        EthernetLayer ethernetLayer = NetworkMethods.GetEthernetLayer(MacAddressSource, MacAddressDestination); //2 Ethernet Layer                        
                        IpV4Layer ipV4Layer = NetworkMethods.GetIpV4Layer(SourceIP, DestinationIP); //3 IPv4 Layer
                        IcmpEchoLayer icmpLayer = new IcmpEchoLayer(); //4 ICMP Layer                        
                        PacketBuilder builder = new PacketBuilder(ethernetLayer, ipV4Layer, icmpLayer); // Create the builder that will build our packets

                        //send stego start sequence
                        string secretInBin = BinaryOperations.stringASCII2BinaryNumber(Secret); //prepare stego message: ascii text to bin
                        if (secretInBin == null)
                        {
                            SettextBoxDebug("Sorry, cannot be sended, non ASCII chars in message.");
                            break;
                        }
                        List<string> partsOfSecretMessage = secretInBin.SplitInParts(16).ToList(); //16 bit for urgent

                        for (int i = 0; i < partsOfSecretMessage.Count;)
                        {
                            try //In each ICMP packet 4 bytes of hidden data can be inserted. The hidden data will be placed in both Identifier (2 bytes) and Sequence number (2 bytes) fields. 
                            {
                                string binValue = partsOfSecretMessage[i++].PadLeft(16, '0');
                                //blockOfSecret.Add(binValue);
                                icmpLayer.Identifier = Convert.ToUInt16(binValue, 2);

                                try
                                {
                                    binValue = partsOfSecretMessage[i++].PadLeft(16, '0');
                                    //blockOfSecret.Add(binValue);
                                    icmpLayer.SequenceNumber = Convert.ToUInt16(binValue, 2);
                                }
                                catch //in case that there are no more letters in string secret previous part, but nothing to sequence
                                {
                                    icmpLayer.SequenceNumber = 0;
                                    //blockOfSecret.Add("0000000000000000");
                                }

                                Packet packet = builder.Build(DateTime.Now); // Rebuild the packet
                                communicator.SendPacket(packet); // Send down the packet //Additional information: Failed writing to device. WinPcap Error: send error: PacketSendPacket failed
                                System.Threading.Thread.Sleep(1000); //wait 1s for sending next one to simulate real network
                            }
                            catch
                            {
                                //in case that there are no more letters in string secret, not nessesary to do anything
                            }
                        }

                        //string final =  string.Join(",", blockOfSecret.ToArray());
                        //SettextBoxDebug(String.Format("Stego: {0}", final));
                        terminate = true;
                    }
                    else if (String.Equals(StegoMethod, Lib.listOfStegoMethods[1])) //TCP
                    {
                        //List<string> blockOfSecret = new List<string>(); //debug only
                        string secretInBin = BinaryOperations.stringASCII2BinaryNumber(Secret); //prepare stego message: ascii text to bin
                        if (secretInBin == null)
                        {
                            SettextBoxDebug("Sorry, cannot be sended, non ASCII chars in message.");
                            break;
                        }

                        string restString = "";
                        int numberOfTakenBits = (secretInBin.Count() >= 31) ? 31 : secretInBin.Count(); //for sequence number from RFC
                        if (numberOfTakenBits > 0)
                        {
                            restString = secretInBin.Substring(0, numberOfTakenBits); //get first 32 bit and remove them //System.ArgumentOutOfRangeException
                        }
                        //blockOfSecret.Add(substring);

                        int seqNumberInDec = Convert.ToInt32(restString, 2); //convert bin to uint for sequence number                        
                        if (seqNumberInDec != 0) //if convert fails
                        {
                            while (seqNumberInDec % 11 == 0 && seqNumberInDec != 0) //number cannot be mod 11, generated number is mod 11
                            {
                                numberOfTakenBits--;
                                restString = secretInBin.Substring(0, numberOfTakenBits);
                                seqNumberInDec = Convert.ToInt32(restString, 2);
                                //blockOfSecret.Add(restString);
                            };

                            seqNumberLocal = (uint)seqNumberInDec; //WARNING
                            ackNumberLocal = 0; //will be sended in first SYN packet
                            if (numberOfTakenBits > 0)
                            {
                                secretInBin = secretInBin.Remove(0, numberOfTakenBits); //remove already used chars in sequence number from secret message
                            }
                        }
                        else
                        {
                            seqNumberLocal = Lib.getSynOrAckRandNumber(); //if converting fails //this number is always % 11 == 0! (by stego not by RFC)
                            ackNumberLocal = 0;
                        }

                        List<string> partsOfSecretMessage = secretInBin.SplitInParts(16).ToList(); //16 bit for urgent

                        //now network processing...
                        EthernetLayer ethernetLayer = NetworkMethods.GetEthernetLayer(MacAddressSource, MacAddressDestination); //2                        
                        IpV4Layer ipv4Vrstva = NetworkMethods.GetIpV4Layer(SourceIP, DestinationIP); //3
                        ipv4Vrstva.Protocol = IpV4Protocol.Tcp; //set ISN

                        /* How it works
                         * client sending SYN               seq = generated         ack = 0
                         * server sending SYNACK            seq = generated         ack = received seq + 1
                         * client sending ACK               seq = received ack      ack = received seq + 1
                         *
                         * client sending PSH, DATA         seq = same as before    ack = same as before
                         * server sending ACK               seq = received ack      ack = received seq + size of data
                         * server sending DATA optional     seq = same as before    ack = same as before
                         * client sending ACK               seq = received ack      ack = received seq + size of data
                         * client sending DATA              seq = same as before    ack = same as before
                         * server sending ACK               seq = received ack      ack = received seq + size of data
                         * client sending DATA              seq = same as before    ack = same as before
                         * ...
                         * server sending ACK               seq = received ack      ack = received seq + size of data
                         * client sending FINACK            seq = same as before    ack = same as before
                         * server sending FINACK            seq = received ack      ack = received seq + 1
                         * client sending ACK               seq = received ack      ack = received seq + 1 
                         */

                        //SYN
                        TcpLayer tcpLayer = NetworkMethods.GetTcpLayer(SourcePort, DestinationPort, seqNumberLocal, ackNumberLocal, TcpControlBits.Synchronize);
                        PacketBuilder builder = new PacketBuilder(ethernetLayer, ipv4Vrstva, tcpLayer);
                        communicator.SendPacket(builder.Build(DateTime.Now)); //Send down the SYN packet

                        SettextBoxDebug(">waiting for TCP SYN ACK");
                        ackNumberLocal = seqNumberLocal + 1; //expected value from oposite side
                        ackNumberRemote = seqNumberLocal + 1; //because we know it

                        //SYN ACK
                        seqNumberRemote = NetworkMethods.WaitForTcpAck(communicator, SourceIP, DestinationIP, SourcePort, DestinationPort, ackNumberRemote, TcpControlBits.Synchronize | TcpControlBits.Acknowledgment); //in ack is expected value
                        if (seqNumberRemote == null)
                        {
                            SettextBoxDebug(">TCP ACK not received!");
                            continue; //retransmission
                        }
                        SettextBoxDebug(">received TCP SYN ACK");
                        seqNumberLocal = ackNumberRemote;
                        ackNumberLocal = (uint)seqNumberRemote + 1;

                        //ACK
                        tcpLayer = NetworkMethods.GetTcpLayer(SourcePort, DestinationPort, seqNumberLocal, ackNumberLocal, TcpControlBits.Acknowledgment);
                        builder = new PacketBuilder(ethernetLayer, ipv4Vrstva, tcpLayer);
                        communicator.SendPacket(builder.Build(DateTime.Now)); //Send down ACK packet

                        //DATA (sliding window not used!)
                        List<String> FAKEdomainsToAsk = new List<string>() { "vsb.cz", "seznam.cz", "google.com", "yahoo.com", "github.com", "uwasa.fi", "microsoft.com", "yr.no", "googlecast.com" }; //used as infinite loop
                        int FAKEindexindomains = 0;

                        for (int i = 0; i < partsOfSecretMessage.Count; i++) //foreach secret message
                        {
                            tcpLayer = NetworkMethods.GetTcpLayer(SourcePort, DestinationPort, seqNumberLocal, ackNumberLocal, TcpControlBits.Acknowledgment | TcpControlBits.Push | TcpControlBits.Urgent);
                            string binValue = partsOfSecretMessage[i].PadLeft(16, '0');
                            //blockOfSecret.Add(binValue);
                            tcpLayer.UrgentPointer = Convert.ToUInt16(binValue, 2); ////stego in urgent field (Unsigned 16-bit integer)

                            //PAYLOAD need to be changed to HTTP
                            DnsLayer dnsLayer = NetworkMethods.GetDnsHeaderLayer(Convert.ToUInt16(binValue, 2)); //total capacity 16 bit, idea to make a XOR
                            dnsLayer.IsResponse = false;
                            if (FAKEindexindomains == FAKEdomainsToAsk.Count)
                            {
                                FAKEindexindomains = 0;
                            }
                            dnsLayer.Queries = new List<DnsQueryResourceRecord>() { NetworkMethods.GetDnsQuery(FAKEdomainsToAsk[FAKEindexindomains++]) };

                            builder = new PacketBuilder(ethernetLayer, ipv4Vrstva, tcpLayer, dnsLayer);
                            Packet packet = builder.Build(DateTime.Now);
                            communicator.SendPacket(packet);

                            //ACK sended DATA
                            uint payloadsize = (uint)packet.Ethernet.IpV4.Tcp.PayloadLength;
                            seqNumberLocal += payloadsize; //expected value from oposite side

                            SettextBoxDebug(">waiting for TCP ACK");
                            seqNumberRemote = NetworkMethods.WaitForTcpAck(communicator, SourceIP, DestinationIP, SourcePort, DestinationPort, seqNumberLocal); //in ack is expected value
                            if (seqNumberRemote == null)
                            {
                                SettextBoxDebug(">TCP ACK not received!");
                                seqNumberRemote = ackNumberLocal;
                                i--; //resend same char
                                continue;
                            }
                            SettextBoxDebug(">received TCP ACK");
                        }

                        //finish TCP connection
                        Stopwatch sw = new Stopwatch(); //for timeout
                        sw.Start();
                        while (true)
                        {
                            if (sw.ElapsedMilliseconds > 20000) //timeout break
                            {
                                sw.Stop();
                                break;
                            }

                            //client's FIN ACK
                            tcpLayer = NetworkMethods.GetTcpLayer(SourcePort, DestinationPort, seqNumberLocal, ackNumberLocal, TcpControlBits.Fin | TcpControlBits.Acknowledgment); //REALLY ACK?
                            builder = new PacketBuilder(ethernetLayer, ipv4Vrstva, tcpLayer);
                            communicator.SendPacket(builder.Build(DateTime.Now)); //Send down the FIN packet

                            //wait for FIN ACK from server
                            SettextBoxDebug(">waiting for TCP ACK (closing)");
                            ackNumberLocal = seqNumberLocal + 1; //expected value from oposite side
                            ackNumberRemote = seqNumberLocal + 1; //because we know it                        
                            seqNumberRemote = NetworkMethods.WaitForTcpAck(communicator, SourceIP, DestinationIP, SourcePort, DestinationPort, ackNumberRemote, TcpControlBits.Fin | TcpControlBits.Acknowledgment); //in ack is expected value
                            if (seqNumberRemote == null)
                            {
                                SettextBoxDebug(">TCP closing ACK not received!");
                                continue; //retransmission
                            }

                            SettextBoxDebug(">received TCP closing ACK");
                            seqNumberLocal = ackNumberRemote;
                            ackNumberLocal = (uint)seqNumberRemote + 1;

                            //send ACK as reply for server's FIN ACK
                            tcpLayer = NetworkMethods.GetTcpLayer(SourcePort, DestinationPort, seqNumberLocal, ackNumberLocal, TcpControlBits.Acknowledgment);
                            builder = new PacketBuilder(ethernetLayer, ipv4Vrstva, tcpLayer);
                            communicator.SendPacket(builder.Build(DateTime.Now));
                            SettextBoxDebug(">communication closed");
                            //string final =  string.Join(",", blockOfSecret.ToArray());
                            //SettextBoxDebug(String.Format("Stego: {0}", final));
                            break;
                        }

                        terminate = true; //terminate thread
                    }
                    else if (String.Equals(StegoMethod, Lib.listOfStegoMethods[2])) //IP
                    {
                        SettextBoxDebug("IP not implemented\n");
                        terminate = true;

                        // Set IPv4 parameters
                        //sipV4Layer.Identification = (ushort)i;
                    }
                    else if (String.Equals(StegoMethod, Lib.listOfStegoMethods[3])) //ISN + IP ID
                    {

                        //nessesary to do TCP handshake
                        //SYN paket obsahuje prázdný TCP segment a má nastavený příznak SYN v TCP hlavičce.                            

                        // Ethernet Layer
                        EthernetLayer ethernetVrstva = NetworkMethods.GetEthernetLayer(MacAddressSource, MacAddressDestination);

                        // IPv4 Layer
                        IpV4Layer ipv4Vrstva = NetworkMethods.GetIpV4Layer(SourceIP, DestinationIP);
                        ipv4Vrstva.TypeOfService = Convert.ToByte(0); //STEGO ready //0 default value
                        ipv4Vrstva.Identification = 555; //STEGO                        

                        //needs to be finalize? ipv4Vrstva.Finalize();

                        // TCPv4 Layer
                        TcpLayer tcpVrstva = NetworkMethods.GetTcpLayer(SourcePort, DestinationPort, Convert.ToUInt32(Secret[1]), 0, TcpControlBits.Synchronize);
                        //Expert Info (Warn/Protocol): Acknowledgment number: Broken TCP. The acknowledge field is nonzero while the ACK flag is not set

                        //what about payload?
                        PayloadLayer payloadVrstva = new PayloadLayer();
                        payloadVrstva.Data = new Datagram(Encoding.ASCII.GetBytes("Just casual payload"));

                        PacketBuilder builder = new PacketBuilder(ethernetVrstva, ipv4Vrstva, tcpVrstva, payloadVrstva); // Create the builder that will build our packets, build the packet, send the packet
                        Packet packet = builder.Build(DateTime.Now);
                        communicator.SendPacket(packet);

                        //send something like wing mark for recognizing it on server side

                        //sending rest of message
                        for (int i = 0; i < Secret.Length;) //because firts two letters are already used
                        {
                            ipv4Vrstva.TypeOfService = Convert.ToByte(Secret[i++]); //STEGO
                            ipv4Vrstva.Identification = Convert.ToUInt16(Secret[i++]);
                            tcpVrstva.ControlBits = TcpControlBits.None;
                            //tcpVrstva.SequenceNumber = should be changed after 2 min of transferring

                            //sending part            
                            builder = new PacketBuilder(ethernetVrstva, ipv4Vrstva, tcpVrstva, payloadVrstva/*httpVrstva*/); //probably not nesseary, editing original allowed, but just for sure
                            packet = builder.Build(DateTime.Now);
                            communicator.SendPacket(packet);

                        }
                        terminate = true;
                    }
                    else if (String.Equals(StegoMethod, Lib.listOfStegoMethods[4])) //DNS
                    {
                        EthernetLayer ethernetLayer = NetworkMethods.GetEthernetLayer(MacAddressSource, MacAddressDestination);
                        IpV4Layer ipV4Layer = NetworkMethods.GetIpV4Layer(SourceIP, DestinationIP);
                        UdpLayer udpLayer = NetworkMethods.GetUdpLayer(SourcePort, 53);

                        //improvement: ask for PTR record, ask for IPs...
                        List<String> domainsToAsk = Lib.listOfDomainsForDNSqueries; 
                        int indexindomains = 0;

                        //List<string> blockOfSecret = new List<string>(); //debug only
                        string secretInBin = BinaryOperations.stringASCII2BinaryNumber(Secret); //prepare stego message: ascii text to bin
                        if (secretInBin == null)
                        {
                            SettextBoxDebug("Sorry, cannot be sended, non ASCII chars in message.");
                            break;
                        }
                        List<string> partsOfSecretMessage = secretInBin.SplitInParts(16).ToList(); //prepare splitted messages

                        foreach (string s in partsOfSecretMessage)
                        {
                            if (indexindomains == domainsToAsk.Count()) //infinite liest
                                indexindomains = 0;

                            string binValue = s.PadLeft(16, '0'); //message padded
                            //blockOfSecret.Add(binValue); //debug

                            DnsLayer dnsLayer = NetworkMethods.GetDnsHeaderLayer(Convert.ToUInt16(binValue, 2)); //total capacity 16 bit
                            dnsLayer.IsResponse = false;
                            dnsLayer.Queries = new List<DnsQueryResourceRecord>() { NetworkMethods.GetDnsQuery(domainsToAsk[indexindomains++]) };

                            PacketBuilder builder = new PacketBuilder(ethernetLayer, ipV4Layer, udpLayer, dnsLayer);
                            Packet packet = builder.Build(DateTime.Now);
                            communicator.SendPacket(packet);

                            System.Threading.Thread.Sleep(900); //wait 1s for sending next one to simulate real network                        
                        }

                        terminate = true;

                    }
                    else
                    {
                        SettextBoxDebug("Nothing happened"); //Additional information: Index was outside the bounds of the array.
                    }

                    SettextBoxDebug(String.Format("Processing of method {0} finished\n", StegoMethod));
                }

            }
            while (!terminate);
        }

        public void SettextBoxDebug(string text)
        {
            try
            {
                Console.WriteLine(text);
                mv.Invoke((MethodInvoker)delegate //An unhandled exception: Cannot access a disposed object when closing app
                {
                    mv.textBoxDebug.Text = text + "\r\n" + mv.textBoxDebug.Text; // runs on UI thread

                });
            }
            catch
            {
                SettextBoxDebug("Printing failed at server location => dont close it when is still sending");
                Environment.Exit(Environment.ExitCode);
                return;
            }
        }

        public void Terminate()
        {
            this.terminate = true;
        }

    }

}
