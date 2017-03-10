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
        public Server(MainWindow mv)
        {
            this.mv = mv;
        }
        public void Terminate()
        {
            this.terminate = true;
        }

        public void Listening() //thread listening method (not inicializator, but "service styled" on background
        {
            if(Lib.checkPrerequisites() == false)
            {
                SettextBoxDebug("Something is wrong!\n");
                return;
            }

            selectedDevice = Lib.allDevices[Lib.getSelectedInterfaceIndex(serverIP)]; // Take the selected adapter
            //Additional information: Index was out of range. Must be non-negative and less than the size of the collection.

            // Open the device // portion of the packet to capture // 65536 guarantees that the whole packet will be captured on all the link layers // promiscuous mode // read timeout
            using (PacketCommunicator communicator = selectedDevice.Open(65536, PacketDeviceOpenAttributes.Promiscuous, 1000))
            {
                SettextBoxDebug(String.Format("Listening on {0} {1}...", serverIP, selectedDevice.Description));

                // Retrieve the packets
                Packet packet;
                do
                {
                    PacketCommunicatorReceiveResult result = communicator.ReceivePacket(out packet);
                    switch (result)
                    {
                        case PacketCommunicatorReceiveResult.Timeout:
                            // Timeout elapsed
                            continue;
                        case PacketCommunicatorReceiveResult.Ok:
                            {

                                //MASTER DISASSEMBLING PACKET
                                //filtering https://github.com/PcapDotNet/Pcap.Net/wiki/Pcap.Net-Tutorial-Filtering-the-traffic

                                //dö a select function


                                //communicator.SetFilter("ip and tcp and icmp"); //Additional information: An error has occured when compiling the filter <ip and tcp and icmp>: expression rejects all packets
                                //Console.WriteLine(packet.Timestamp.ToString("yyyy-MM-dd hh:mm:ss.fff") + " length:" + packet.Length);



                                ProcessIncomingPacket(packet); //Object reference not set to an instance of an object.
                                //Thread.Sleep(1000);
                                break;
                            }
                        default:
                            throw new InvalidOperationException("The result " + result + " shoudl never be reached here");
                    }
                } while (!terminate);

                return;
            }
        }
        public void SettextBoxDebug(string text)
        {        
            mv.Invoke((MethodInvoker)delegate
            {
                mv.textBoxDebug.Text = text + mv.textBoxDebug.Text; // runs on UI thread
            });
            //reason: Operace mezi vlákny není platná: Přístup k ovládacímu prvku textBoxDebug proběhl z jiného vlákna než z vlákna, v rámci kterého byl vytvořen.
        }

        private void ProcessIncomingPacket(Packet packet)
        {

            if (String.Equals(StegoMethod, Lib.listOfStegoMethods[0])) //IP
            {
                SettextBoxDebug("Vybrana moznost 1");
            }

            //selector na výpis opět podle metody + nějaký univerzální

            //TODO: Solve this!

            //SettextBoxDebug(packet.IpV4.Identification.ToString());
            //this.textBoxDebug.Text = packet.IpV4.Identification.ToString();

            SettextBoxDebug(String.Format("> {0}\n", packet.IpV4.Payload.ToString()));

            /*
            IpV4Datagram ip = packet.Ethernet.IpV4;
            UdpDatagram udp = ip.Udp;
            */
        }


        //WTF what is this?
        private void PacketHandler(Packet packet) // Callback function invoked by Pcap.Net for every incoming packet
        {
            SettextBoxDebug(String.Format("{0} length: {1}", packet.Timestamp.ToString("yyyy-MM-dd hh:mm:ss.fff"), packet.Length));
        }




    }
}
