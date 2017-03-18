using System;
using System.Collections.Generic;
using PcapDotNet.Core;
using PcapDotNet.Packets;
using System.Windows.Forms;
using PcapDotNet.Packets.IpV4;

namespace SteganographyFramework
{
    public class Server
    {
        public volatile bool terminate = false;
        public IpV4Address serverIP { get; set; }

        private MainWindow mv; //not good
        private PacketDevice selectedDevice = null;
        //private string secret = "";
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

            selectedDevice = Lib.allDevices[Lib.getSelectedInterfaceIndex(serverIP)]; // Take the selected adapter

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

                Packet packet; // Retrieve the packets
                do
                {
                    SettextBoxDebug("Working...");
                    PacketCommunicatorReceiveResult result = communicator.ReceivePacket(out packet);
                    switch (result)
                    {
                        case PacketCommunicatorReceiveResult.Timeout: // Timeout elapsed
                            continue;
                        case PacketCommunicatorReceiveResult.Ok:
                            {
                                SettextBoxDebug("Processing...");
                                communicator.ReceivePackets(0, ProcessIncomingPacket);
                                //communicator.ReceiveSomePackets(0, ProcessIncomingPacket);
                                //ProcessIncomingPacket(packet);
                                /*
                                if (packet.IsValid) //to by bylo lepší dělat filtrem  //&& packet.IpV4.CurrentDestination == serverIP
                                {
                                    ProcessIncomingPacket(packet);
                                }
                                */
                                break;
                            }
                        default:
                            throw new InvalidOperationException("The result " + result + " shoudl never be reached here");
                    }
                } while (!terminate);

                SettextBoxDebug(String.Format("Secret in this session: {0}", GetSecretMessage(capturedPackets, StegoMethod)));
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

        public void ProcessIncomingPacket(Packet packet) //switch back to private
        {
            string secret = "";
            SettextBoxDebug((packet.Timestamp.ToString("yyyy-MM-dd hh:mm:ss.fff") + " length:" + packet.Length));

            if (packet.IpV4.Udp.IsValid) //UDP methods
            {
                if (packet.IpV4.Udp.DestinationPort == DestinationPort)
                {
                    SettextBoxDebug("Magic");
                }
                else if (packet.IpV4.Udp.DestinationPort == 53)
                {
                    SettextBoxDebug("DNS 53");
                }
                else
                {
                    //TODO: split section for this which contains magic and garbage from network
                    SettextBoxDebug("UDP balast");
                }
            }
            else if (packet.IpV4.Tcp.IsValid) //general
            {
                if (String.Equals(StegoMethod, Lib.listOfStegoMethods[1])) //TCP
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

                if (String.Equals(StegoMethod, Lib.listOfStegoMethods[3])) //ISN + IP ID
                {
                    int recognizedDestPort;
                    bool isNumeric = int.TryParse("packet.IpV4.Tcp.DestinationPort", out recognizedDestPort); //protection
                    if (isNumeric && recognizedDestPort == DestinationPort)
                    {
                        capturedPackets.Add(packet);
                    }
                }
            }
            else if (packet.IpV4.Icmp.IsValid)
            {
                if (String.Equals(StegoMethod, Lib.listOfStegoMethods[0])) //ICMP
                {

                }
            }
            else if (packet.IpV4.IsValid)
            {
                if (String.Equals(StegoMethod, Lib.listOfStegoMethods[2])) //IP
                {
                    SettextBoxDebug("Vybrana moznost 2");
                }
            }
            else
            {
                SettextBoxDebug("Not fits to any criteria");
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
