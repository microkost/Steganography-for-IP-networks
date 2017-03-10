using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Threading;

//PREBRAT
using PcapDotNet.Base;
using PcapDotNet.Core;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Arp;
using PcapDotNet.Packets.Dns;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.Gre;
using PcapDotNet.Packets.Http;
using PcapDotNet.Packets.Icmp;
using PcapDotNet.Packets.Igmp;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.IpV6;
using PcapDotNet.Packets.Transport;
using System.Windows.Forms;

namespace RawSocket
{
    public class Server
    {
        public volatile bool terminate = false;
        public string serverIP { get; set; }

        private MainWindow mv; //not good
        private PacketDevice selectedDevice = null;
        private string secret = "";
        public int DestinationPort { get; set; } //port on which is server listening //is listening on all
        public string StegoMethod { get; set; } //contains name of choosen method

        private List<Packet> capturedPackets;
        public Server(MainWindow mv)
        {
            this.mv = mv;
            capturedPackets = new List<Packet>();
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

            secret = ""; //reset message

            selectedDevice = Lib.allDevices[Lib.getSelectedInterfaceIndex(serverIP)]; // Take the selected adapter
            //Additional information: Index was out of range. Must be non-negative and less than the size of the collection.

            // Open the device // portion of the packet to capture // 65536 guarantees that the whole packet will be captured on all the link layers // promiscuous mode // read timeout
            using (PacketCommunicator communicator = selectedDevice.Open(65536, PacketDeviceOpenAttributes.Promiscuous, 1000))
            {
                SettextBoxDebug(String.Format("Listening on {0} {1}...", serverIP, selectedDevice.Description));
                /*
                using (BerkeleyPacketFilter filter = communicator.CreateFilter("udp")) //remove UDP //check if really remove UDP
                {
                    SettextBoxDebug(String.Format("Filter set to remove UDP"));
                    communicator.SetFilter(filter);
                }
                */

                // Retrieve the packets
                Packet packet;
                do
                {
                    PacketCommunicatorReceiveResult result = communicator.ReceivePacket(out packet);
                    switch (result)
                    {
                        case PacketCommunicatorReceiveResult.Timeout: // Timeout elapsed
                            continue;
                        case PacketCommunicatorReceiveResult.Ok:
                            {
                                ProcessIncomingPacket(packet);
                                break;
                            }
                        default:
                            throw new InvalidOperationException("The result " + result + " shoudl never be reached here");
                    }
                } while (!terminate);

                secret = GetSecretMessage(capturedPackets, StegoMethod);
                SettextBoxDebug(String.Format("Final secret: {0}", secret));
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

        public static Packet ProcessIncomingPacketExternally(Packet packet)
        {
            return packet;
        }
        public void ProcessIncomingPacket(Packet packet) //switch back to private
        {
            if (packet.IpV4 != null && packet.IpV4.Udp == null) //check packet for IPv4 and is not UDP, because we are not interested by UDP
            {
                SettextBoxDebug((packet.Timestamp.ToString("yyyy-MM-dd hh:mm:ss.fff") + " length:" + packet.Length));

                if (String.Equals(StegoMethod, Lib.listOfStegoMethods[0])) //ICMP
                {

                }
                else if (String.Equals(StegoMethod, Lib.listOfStegoMethods[1])) //TCP
                {
                    int recognizedDestPort;
                    bool isNumeric = int.TryParse("packet.IpV4.Tcp.DestinationPort", out recognizedDestPort); //protection
                    if (isNumeric && recognizedDestPort == DestinationPort)
                    {
                        char receivedChar = Convert.ToChar(packet.IpV4.TypeOfService);
                        secret += receivedChar;
                        SettextBoxDebug(String.Format("received: {0}", receivedChar));
                    }
                }
                else if (String.Equals(StegoMethod, Lib.listOfStegoMethods[2])) //IP
                {
                    SettextBoxDebug("Vybrana moznost 2");
                }
                else if (String.Equals(StegoMethod, Lib.listOfStegoMethods[3])) //ISN + IP ID
                {
                    int recognizedDestPort;
                    bool isNumeric = int.TryParse("packet.IpV4.Tcp.DestinationPort", out recognizedDestPort); //protection
                    if (isNumeric && recognizedDestPort == DestinationPort)
                    {
                        capturedPackets.Add(packet);
                    }
                }
            }

        }
        private string GetSecretMessage(List<Packet> packets, string usedMethod)
        {
            string output = "";

            if (packets == null || packets.Count == 0) //protection only
                return "nothing to process";

            if (String.Equals(usedMethod, Lib.listOfStegoMethods[3]))
            {                                
                foreach (Packet p in packets)
                {
                    output += Convert.ToChar(p.IpV4.TypeOfService);
                    output += Convert.ToChar(p.IpV4.Identification);

                    if (p.IpV4.Tcp.Http.Body != null)
                        output += p.IpV4.Tcp.Http.Body.ToString();

                    if (p.IpV4.Tcp.Payload != null)
                        output += p.IpV4.Tcp.Payload.ToString();
                }
            }

            packets.Clear();
            return output;
        }
    }
}
