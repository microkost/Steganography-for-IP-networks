using System;
using System.Collections.Generic;
using PcapDotNet.Core;
using PcapDotNet.Packets;
using System.Windows.Forms;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.Icmp;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.Transport;
using PcapDotNet.Packets.Dns;

namespace SteganographyFramework
{
    public class Server
    {
        public volatile bool terminate = false;
        public IpV4Address serverIP { get; set; }

        private MainWindow mv; //not good
        private PacketDevice selectedDevice = null;

        public int DestinationPort { get; set; } //port on which is server listening //is listening on all
        public string StegoMethod { get; set; } //contains name of choosen method
        public ushort SourcePort { get; private set; }
        private uint ackNumberLocal { get; set; } //for TCP answers
        private uint ackNumberRemote { get; set; } //for TCP answers
        private uint seqNumberLocal { get; set; } //for TCP answers
        private uint seqNumberRemote { get; set; } //for TCP answers
        private uint? seqNumberBase { get; set; }
        private uint ackNumberBase { get; set; }

        private List<Tuple<Packet, String>> StegoPackets; //contains steganography to process

        public Server(MainWindow mv)
        {
            this.mv = mv;
            StegoPackets = new List<Tuple<Packet, String>>();
            seqNumberBase = null;      
        }
        public void Terminate()
        {
            this.terminate = true;
        }

        public void Listening() //thread listening method (not inicializator, but "service styled" on background)
        {
            if (Lib.checkPrerequisites() == false)
            {
                SettextBoxDebug("Something is wrong!\n");
                return;
            }

            selectedDevice = Lib.allDevices[Lib.getSelectedInterfaceIndex(serverIP)]; // Take the selected adapter

            using (PacketCommunicator communicator = selectedDevice.Open(65536, PacketDeviceOpenAttributes.Promiscuous, 1000))
            {
                //Parametres: Open the device // portion of the packet to capture // 65536 guarantees that the whole packet will be captured on all the link layers // promiscuous mode // read timeout
                SettextBoxDebug(String.Format("Listening on {0} {1}...", serverIP, selectedDevice.Description));
                
                string filter = String.Format("tcp port {0} or icmp or udp port 53 and not src port 53", DestinationPort); //be aware of ports when server is replying to request (DNS), filter catch again response => loop
                communicator.SetFilter(filter); // Compile and set the filter //needs try-catch for new or dynamic filter
                //Changing process: implement new method and capture traffic through Wireshark, prepare & debug filter then extend local filtering string by new rule
                //syntax of filter https://www.winpcap.org/docs/docs_40_2/html/group__language.html

                Packet packet; // Retrieve the packets
                do
                {
                    SettextBoxDebug("Listening...");
                    PacketCommunicatorReceiveResult result = communicator.ReceivePacket(out packet);
                    switch (result)
                    {
                        case PacketCommunicatorReceiveResult.Timeout: // Timeout elapsed
                            continue;
                        case PacketCommunicatorReceiveResult.Ok:
                            {
                                //SettextBoxDebug(">Processing...");
                                if (packet.IsValid && packet.IpV4 != null) //only IPv4
                                    ProcessIncomingV4Packet(packet);
                                //communicator.ReceivePackets(0, ProcessIncomingV4Packet); //problems with returning from this method
                                break;
                            }
                        default:
                            throw new InvalidOperationException("The result " + result + " shoudl never be reached here");
                    }
                } while (!terminate);

                SettextBoxDebug(String.Format("Message is assembling from {0} packets", StegoPackets.Count));
                string secret = GetSecretMessage(StegoPackets); //process result of steganography
                SettextBoxDebug(String.Format("Secret in this session: {0}", secret));
                StegoPackets.Clear();
                return;
            }
        }
        public void SettextBoxDebug(string text) //printing function for almost all windows
        {
            try
            {
                mv.Invoke((MethodInvoker)delegate //An unhandled exception: Cannot access a disposed object when closing app
                {
                    mv.textBoxDebug.Text = text + "\r\n" + mv.textBoxDebug.Text; // runs on UI thread
                });
            }
            catch
            {
                SettextBoxDebug("Printing failed at server location => dont close it when is still listening"); //temporary solution
                mv.Close();
            }
        }

        public void ProcessIncomingV4Packet(Packet packet) //recognizing steganography, collect it and reply if nessesary
        {
            IpV4Datagram ip = packet.Ethernet.IpV4;
            if (ip.IsValid == false)
                return;

            //SettextBoxDebug(">>IPv4 " + (packet.Timestamp.ToString("yyyy-MM-dd hh:mm:ss.fff") + " length:" + packet.Length));

            IcmpIdentifiedDatagram icmp = null;
            if (ip.Icmp.IsValid == true)
            {
                icmp = (IcmpIdentifiedDatagram)ip.Icmp; //parsing layers for processing            
            }

            TcpDatagram tcp = ip.Tcp; //needs also try catch solution?
            UdpDatagram udp = ip.Udp;
            DnsDatagram dns = udp.Dns;

            //try to recognize magic sequence //some state construction //maybe recognize IP from which is going traffic
            //if magic processing save packet to StegoPackets.Add(new Tuple<Packet, String>(packet, StegoMethod));
            //MAGIC should reply with "reply 0 / destination unrecheable 3 / time exceeded 11
            //until server believes that messages contains magic, needs to remember source IP

            /*//not nessesary test port here cause of first filter
            int recognizedDestPort;
            bool isNumeric = int.TryParse("packet.IpV4.Tcp.DestinationPort", out recognizedDestPort);
            if (isNumeric && recognizedDestPort == DestinationPort)*/

            //ICMP methods
            if (icmp != null && icmp.IsValid && String.Equals(StegoMethod, Lib.listOfStegoMethods[0]))
            {
                SettextBoxDebug(">>Adding ICMP...");
                StegoPackets.Add(new Tuple<Packet, String>(packet, StegoMethod));

                if (icmp.GetType() == typeof(IcmpEchoDatagram)) //if icmp request than send reply
                {
                    SettextBoxDebug(">>Replying ICMP...");

                    EthernetLayer ethernetLayer = NetworkMethods.GetEthernetLayer(packet.Ethernet.Destination, packet.Ethernet.Source); //reversed order of MAC addresses
                    IpV4Layer ipV4Layer = NetworkMethods.GetIpV4Layer(serverIP, ip.Source); //reversed order of IP addresses

                    IcmpEchoReplyLayer icmpLayer = new IcmpEchoReplyLayer();
                    icmpLayer.SequenceNumber = icmp.SequenceNumber;
                    icmpLayer.Identifier = icmp.Identifier;

                    PacketBuilder builder = new PacketBuilder(ethernetLayer, ipV4Layer, icmpLayer);
                    SendReplyPacket(builder.Build(DateTime.Now)); //send immeiaditelly
                }
            }

            //TCP methods
            else if (tcp != null && tcp.IsValid && String.Equals(StegoMethod, Lib.listOfStegoMethods[1]))
            {
                if (tcp.DestinationPort != DestinationPort)
                    return;

                EthernetLayer ethernetLayer = NetworkMethods.GetEthernetLayer(packet.Ethernet.Destination, packet.Ethernet.Source); //reversed order of MAC addresses
                IpV4Layer ipV4Layer = NetworkMethods.GetIpV4Layer(serverIP, ip.Source); //reversed order of IP addresses     
                ipV4Layer.Protocol = IpV4Protocol.Tcp; //set ISN

                seqNumberRemote = tcp.SequenceNumber;
                ackNumberRemote = tcp.AcknowledgmentNumber;
                TcpLayer tcLayer;
                PacketBuilder builder;

                /* How it works
                 * client sending SYN               seq = generated         ack = 0
                 * server sending SYNACK            seq = generated         ack = received seq + 1
                 * client sending ACK               seq = received ack      ack = received seq + 1
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

                if (tcp.ControlBits == TcpControlBits.Synchronize) //receive SYN
                {
                    SettextBoxDebug(">>Replying with TCP SYN/ACK...");
                    seqNumberLocal = 200; //Lib.getSynOrAckRandNumber();
                    ackNumberLocal = seqNumberRemote;
                    seqNumberBase = seqNumberLocal; //setting value is enstablished connection, setting to null is terminating
                    ackNumberBase = ackNumberLocal;
                    ackNumberLocal++;
                    tcLayer = NetworkMethods.GetTcpLayer(tcp.DestinationPort, tcp.SourcePort, seqNumberLocal, ackNumberLocal, TcpControlBits.Synchronize | TcpControlBits.Acknowledgment);
                    builder = new PacketBuilder(ethernetLayer, ipV4Layer, tcLayer);
                    SendReplyPacket(builder.Build(DateTime.Now)); //send immediatelly
                    return;
                }

                if (seqNumberBase == null) //test of enstablished connection
                    return;

                if (tcp.ControlBits == TcpControlBits.Fin || tcp.ControlBits == (TcpControlBits.Fin | TcpControlBits.Acknowledgment)) //receive FIN or FIN ACK
                {
                    seqNumberLocal = ackNumberRemote;
                    ackNumberLocal = seqNumberRemote + 1;
                    
                    SettextBoxDebug(">>Ending TCP connection with FINACK"); //SEND ALSO FIN ACK
                    tcLayer = NetworkMethods.GetTcpLayer(tcp.DestinationPort, tcp.SourcePort, seqNumberLocal, ackNumberLocal, TcpControlBits.Fin | TcpControlBits.Acknowledgment); //seq generated, ack = syn+1
                    builder = new PacketBuilder(ethernetLayer, ipV4Layer, tcLayer);
                    SendReplyPacket(builder.Build(DateTime.Now));

                    //wait for ACK, ideally

                    seqNumberBase = null; //reset enstablished connection
                    return;
                }

                seqNumberLocal = ackNumberRemote;
                ackNumberLocal = (uint)(seqNumberRemote + tcp.PayloadLength);
                if ((tcp.ControlBits & TcpControlBits.Acknowledgment)>0 && (seqNumberLocal-seqNumberBase==1) && (ackNumberLocal - ackNumberBase == 1)) //receive ACK
                {
                    SettextBoxDebug(">>Handshake complete!");
                    return;
                }                

                SettextBoxDebug(">>Adding TCP..."); //before first adding check PSH: Push Function
                StegoPackets.Add(new Tuple<Packet, String>(packet, StegoMethod));

                SettextBoxDebug(">>Replying with ACK...");
                tcLayer = NetworkMethods.GetTcpLayer(tcp.DestinationPort, tcp.SourcePort, seqNumberLocal, ackNumberLocal, TcpControlBits.Acknowledgment); //seq generated, ack = syn+1
                builder = new PacketBuilder(ethernetLayer, ipV4Layer, tcLayer);
                SendReplyPacket(builder.Build(DateTime.Now)); //send immediatelly              
            }


            else if (ip != null && ip.IsValid && tcp.IsValid && String.Equals(StegoMethod, Lib.listOfStegoMethods[3])) //ISN + IP ID
            {
                SettextBoxDebug(">>Adding ISN+IP...");
                StegoPackets.Add(new Tuple<Packet, String>(packet, StegoMethod));
            }

            //IP methods
            else if (ip != null && ip.IsValid && String.Equals(StegoMethod, Lib.listOfStegoMethods[2])) //IP
            {
                SettextBoxDebug(">>Adding IP...");
                StegoPackets.Add(new Tuple<Packet, String>(packet, StegoMethod));
            }

            //DNS methods
            else if (dns != null && dns.IsValid && String.Equals(StegoMethod, Lib.listOfStegoMethods[4])) //DNS
            {
                SettextBoxDebug(">>Adding DNS...");
                StegoPackets.Add(new Tuple<Packet, String>(packet, StegoMethod));

                SettextBoxDebug(">>Replying DNS...");

                EthernetLayer ethernetLayer = NetworkMethods.GetEthernetLayer(packet.Ethernet.Destination, packet.Ethernet.Source); //reversed order
                IpV4Layer ipV4Layer = NetworkMethods.GetIpV4Layer(serverIP, ip.Source); //reversed order
                UdpLayer udpLayer = NetworkMethods.GetUdpLayer(53, udp.SourcePort); //reverse order
                DnsLayer dnsLayer = NetworkMethods.GetDnsHeaderLayer(dns.Id);
                dnsLayer.IsResponse = true;
                dnsLayer.Queries = dns.Queries; //include original request

                List<DnsDataResourceRecord> answers = new List<DnsDataResourceRecord>(); //used for collecting answers if they came in list
                foreach (DnsQueryResourceRecord rec in dns.Queries)
                {
                    answers.Add(NetworkMethods.GetDnsAnswer(rec.DomainName, rec.DnsType, NetworkMethods.getIPfromHostnameViaDNS(rec.DomainName.ToString()).ToString()));
                    //cannot answer for IPv6
                }
                dnsLayer.Answers = answers;

                PacketBuilder builder = new PacketBuilder(ethernetLayer, ipV4Layer, udpLayer, dnsLayer);
                SendReplyPacket(builder.Build(DateTime.Now));
            }

            else
            {
                SettextBoxDebug(">>Nothing fits to any criteria... Is correct method selected?");
            }

            return;
        }
        private string GetSecretMessage(List<Tuple<Packet, String>> MessageIncluded)
        {
            string output = ""; //for final message

            if (MessageIncluded == null || MessageIncluded.Count == 0) //protection only
                return "no message received";

            foreach (Tuple<Packet, String> t in MessageIncluded)
            {
                Packet packet = t.Item1; //for readibility and reusability
                String method = t.Item2;

                IpV4Datagram ip = packet.Ethernet.IpV4;
                if (ip.IsValid == false)
                    break;

                IcmpIdentifiedDatagram icmp = null;
                if (ip.Icmp.IsValid == true)
                {
                    icmp = (IcmpIdentifiedDatagram)ip.Icmp; //parsing layers for processing            
                }

                TcpDatagram tcp = ip.Tcp;
                UdpDatagram udp = ip.Udp;
                DnsDatagram dns = udp.Dns;

                if (String.Equals(method, Lib.listOfStegoMethods[0])) //ICMP
                {
                    SettextBoxDebug(">>>Resolving ICMP...");

                    if (icmp.GetType() == typeof(IcmpEchoDatagram))
                    {
                        output += (char)icmp.Identifier;
                        output += (char)icmp.SequenceNumber;
                    }

                }

                else if (String.Equals(method, Lib.listOfStegoMethods[1])) //TCP
                {
                    SettextBoxDebug(">>>Resolving TCP...");
                    try
                    {
                        char receivedChar = Convert.ToChar(packet.IpV4.TypeOfService);
                        output += receivedChar;
                    }
                    catch
                    {
                        //TODOSOMETHING
                    }

                }

                else if (String.Equals(method, Lib.listOfStegoMethods[2])) //IP
                {
                    output += "E!";
                }

                else if (String.Equals(method, Lib.listOfStegoMethods[3])) //ISN + IP ID
                {
                    output += Convert.ToChar(packet.IpV4.TypeOfService);
                    output += Convert.ToChar(packet.IpV4.Identification);

                    /*
                    if (packet.IpV4.Tcp.Http.Body != null)
                        output += packet.IpV4.Tcp.Http.Body.ToString();

                    if (packet.IpV4.Tcp.Payload != null)
                        output += packet.IpV4.Tcp.Payload.ToString();
                        */
                }

                else if (String.Equals(method, Lib.listOfStegoMethods[4])) //DNS
                {
                    output += Convert.ToChar(dns.Id);
                }

            }

            MessageIncluded.Clear();
            return output;
        }

        public void SendReplyPacket(Packet packet) //universal anwering method
        {
            using (PacketCommunicator communicator = Lib.allDevices[Lib.getSelectedInterfaceIndex(serverIP)].Open(100, PacketDeviceOpenAttributes.Promiscuous, 1000))  //name of the device //size // promiscuous mode // read timeout
            {
                communicator.SendPacket(packet);
            }
            return;
        }
    }
}
