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

        private List<Tuple<Packet, String>> StegoPackets; //contains steganography to process

        public Server(MainWindow mv)
        {
            this.mv = mv;
            StegoPackets = new List<Tuple<Packet, String>>();
        }
        public void Terminate()
        {
            this.terminate = true;
        }

        public void Listening() //thread listening method (not inicializator, but "service styled" on background
        {
            if (Lib.checkPrerequisites() == false)
            {
                SettextBoxDebug("Something is wrong!\n");
                return;
            }

            selectedDevice = Lib.allDevices[Lib.getSelectedInterfaceIndex(serverIP)]; // Take the selected adapter

            // Open the device // portion of the packet to capture // 65536 guarantees that the whole packet will be captured on all the link layers // promiscuous mode // read timeout
            using (PacketCommunicator communicator = selectedDevice.Open(65536, PacketDeviceOpenAttributes.Promiscuous, 1000))
            {
                SettextBoxDebug(String.Format("Listening on {0} {1}...", serverIP, selectedDevice.Description));

                string filter = String.Format("tcp port {0} or icmp or udp port 53", DestinationPort);
                communicator.SetFilter(filter); // Compile and set the filter
                //Changing process: implement new method and capture traffic through Wireshark, prepare filter then extend local filtering string by new rule

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
                                SettextBoxDebug(">Processing...");
                                if (packet.IsValid && packet.IpV4 != null)
                                    ProcessIncomingV4Packet(packet);
                                    //communicator.ReceivePackets(0, ProcessIncomingV4Packet); //only IPv4
                                break;
                            }
                        default:
                            throw new InvalidOperationException("The result " + result + " shoudl never be reached here");
                    }
                } while (!terminate);

                string secret = GetSecretMessage(StegoPackets);
                SettextBoxDebug(String.Format("Secret in this session: {0}", secret));
                return;
            }
        }
        public void SettextBoxDebug(string text) //state printing function for main window
        {
            mv.Invoke((MethodInvoker)delegate
            {
                mv.textBoxDebug.Text = text + "\r\n" + mv.textBoxDebug.Text; // runs on UI thread
            });
        }

        public void ProcessIncomingV4Packet(Packet packet) //recognizing steganography, collect it and reply if nessesary
        {
            IpV4Datagram ip = packet.Ethernet.IpV4;
            if (ip.IsValid == false)
                return;

            IcmpDatagram icmp = ip.Icmp; //parsing layers
            TcpDatagram tcp = ip.Tcp;
            UdpDatagram udp = ip.Udp;
            DnsDatagram dns = udp.Dns;

            //SettextBoxDebug(">>IPv4 " + (packet.Timestamp.ToString("yyyy-MM-dd hh:mm:ss.fff") + " length:" + packet.Length));

            //try to recognize magic sequence //some state construction //maybe recognize IP from which is going traffic
            //if magic processing save packet to StegoPackets.Add(new Tuple<Packet, String>(packet, StegoMethod));

            //ICMP methods
            if (icmp.IsValid && String.Equals(StegoMethod, Lib.listOfStegoMethods[0]))
            {
                SettextBoxDebug(">>Adding ICMP...");
                StegoPackets.Add(new Tuple<Packet, String>(packet, StegoMethod));

                if (packet.IpV4.Icmp.GetType() == typeof(IcmpEchoLayer)) //if icmp request than send reply
                {
                    SettextBoxDebug(">>Reply ICMP...");

                    EthernetLayer ethernetLayer = new EthernetLayer(); //TODO: Call methods from CLIENT class GetEthernetLayer
                    ethernetLayer.Source = packet.Ethernet.Destination;
                    ethernetLayer.Destination = packet.Ethernet.Source;

                    IpV4Layer ipV4Layer = new IpV4Layer();
                    ipV4Layer.CurrentDestination = packet.IpV4.Source;
                    ipV4Layer.Source = serverIP;

                    IcmpEchoReplyLayer icmpLayer = new IcmpEchoReplyLayer();

                    PacketBuilder builder = new PacketBuilder(ethernetLayer, ipV4Layer, icmpLayer);
                    SendReplyPacket(builder.Build(DateTime.Now));
                }
            }

            //TCP methods
            else if (tcp.IsValid && String.Equals(StegoMethod, Lib.listOfStegoMethods[1]))
            {
                /*//not nessesary test port here cause of first filter
                int recognizedDestPort;
                bool isNumeric = int.TryParse("packet.IpV4.Tcp.DestinationPort", out recognizedDestPort);
                if (isNumeric && recognizedDestPort == DestinationPort)*/

                SettextBoxDebug(">>Adding TCP...");
                StegoPackets.Add(new Tuple<Packet, String>(packet, StegoMethod));
            }


            else if (ip.IsValid && tcp.IsValid && String.Equals(StegoMethod, Lib.listOfStegoMethods[3])) //ISN + IP ID
            {
                SettextBoxDebug(">>Adding ISN+IP...");
                StegoPackets.Add(new Tuple<Packet, String>(packet, StegoMethod));
            }

            //IP methods
            else if (ip.IsValid && String.Equals(StegoMethod, Lib.listOfStegoMethods[2])) //IP
            {
                SettextBoxDebug(">>Adding IP...");
                StegoPackets.Add(new Tuple<Packet, String>(packet, StegoMethod));
            }

            //DNS methods
            else if (dns.IsValid && String.Equals(StegoMethod, Lib.listOfStegoMethods[4])) //DNS
            {
                SettextBoxDebug(">>Adding DNS...");
                StegoPackets.Add(new Tuple<Packet, String>(packet, StegoMethod));
            }

            else
            {
                SettextBoxDebug(">>Nothing fits to any criteria... Is right method selected?");
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

                IcmpDatagram icmp = ip.Icmp; //parsing layers
                TcpDatagram tcp = ip.Tcp;
                UdpDatagram udp = ip.Udp;
                DnsDatagram dns = udp.Dns;

                if (String.Equals(method, Lib.listOfStegoMethods[0])) //ICMP
                {
                    SettextBoxDebug(">>>Resolving ICMP...");

                    //IcmpMessageType MessageType = packet.IpV4.ExtractLayer();  //LayerMessageType();
                    // 'PcapDotNet.Packets.ILayer'

                    Datagram datagram = icmp.Payload;
                    


                IcmpEchoLayer icmpLayer = (IcmpEchoLayer)packet.IpV4.Icmp.ExtractLayer(); //Additional information: Unable to cast object of type 'PcapDotNet.Packets.IpV4.IpV4Layer' to type 'PcapDotNet.Packets.Icmp.IcmpEchoLayer'.
                    //Additional information: Unable to cast object of type 'PcapDotNet.Packets.Icmp.IcmpUnknownLayer' to type 'PcapDotNet.Packets.Icmp.IcmpEchoLayer'.
                    output += icmpLayer.Identifier;
                    output += icmpLayer.SequenceNumber;
                }

                else if (String.Equals(method, Lib.listOfStegoMethods[1])) //TCP
                {
                    SettextBoxDebug(">>>Resolving TCP...");
                    char receivedChar = Convert.ToChar(packet.IpV4.TypeOfService);
                    output += receivedChar;

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
                    output += "E!";
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
