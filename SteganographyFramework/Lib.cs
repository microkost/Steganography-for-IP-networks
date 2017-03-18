using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

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

namespace SteganographyFramework
{
    public static class Lib
    {
        public static List<String> listOfStegoMethods = new List<String>() { "ICMP", "TCP", "IP", "ISN + IP ID", "DNS" };

        public static IList<LivePacketDevice> allDevices = LivePacketDevice.AllLocalMachine; //list of available devices       

        public static PacketDevice selectedDevice; //which device will be used for communication
        public static int getSelectedInterfaceIndex(IpV4Address tmpIp) //returns index of selected interface to be selected for communication
        {
            //exceptions when is notinitialized! Missing protection! Add open device section

            int deviceIndex = 0, i = 0; //for device ID
            bool exit = false;

            foreach (LivePacketDevice lpd in allDevices)
            {
                if (exit)
                {
                    break;
                }

                foreach (DeviceAddress nonparsed in lpd.Addresses)
                {
                    string tmp = nonparsed.ToString();
                    string[] words = tmp.Split(' ');

                    if (String.Equals(words[2], tmpIp)) ////should be more effective by filtering IPv6
                    {
                        deviceIndex = i;
                        //SettextBoxDebug(String.Format("Selected interface with {0}\r\n", words[2]));
                        exit = true;
                        break;
                    }
                    else
                    {
                        i++;
                    }
                }
            }

            if (allDevices.Count <= i) //TODO better!
            {
                deviceIndex = 0; //TODO DONT FORGET!
                //Lib.SettextBoxDebug(String.Format("Error in selecting interface, choosing the first.\r\n"));
            }

            return (deviceIndex);
        }
        public static bool checkPrerequisites()
        {
            if (allDevices == null)
                return false;

            if (allDevices.Count == 0)
                //SettextBoxDebug("No interfaces found! Make sure WinPcap is installed.\n");
                return false;

            return true;
        }
        
        public static MacAddress getDestinationMacAddress(PacketCommunicator communicator, IpV4Address ipAddress) //because destination mac address needs to be requested for network
        {
            //build arp request
            //send it
            //wait for arp respond

            //BAAAAAD!
            /*
            EthernetLayer ethernetLayer = new EthernetLayer
                {
                    Source = new MacAddress("01:01:01:01:01:01"),
                    //Destination = new MacAddress("02:02:02:02:02:02"),
                    EtherType = EthernetType.None, // Will be filled automatically.
                };

            ArpLayer arpLayer = new ArpLayer
                {
                    ProtocolType = EthernetType.IpV4,
                    Operation = ArpOperation.Request,
                    SenderHardwareAddress = new byte[] { 3, 3, 3, 3, 3, 3 }.AsReadOnly(), // 03:03:03:03:03:03.
                    SenderProtocolAddress = new byte[] { 1, 2, 3, 4 }.AsReadOnly(), // 1.2.3.4.
                    TargetHardwareAddress = new byte[] { 4, 4, 4, 4, 4, 4 }.AsReadOnly(), // 04:04:04:04:04:04.
                    TargetProtocolAddress = new byte[] { 11, 22, 33, 44 }.AsReadOnly(), // 11.22.33.44.
                };

            PacketBuilder builder = new PacketBuilder(ethernetLayer, arpLayer);

            Packet packet = builder.Build(DateTime.Now);
            */

            /* DEMO TCP!!!
            communicator.SetFilter("tcp and src " + DestinationIpV4 + " and dst " + SourceIpV4 + " and src port " + _destinationPort + " and dst port " + _sourcePort);
            Packet packet;
            while (true)
            {
                if (communicator.ReceivePacket(out packet) == PacketCommunicatorReceiveResult.Ok)
                {
                    Console.WriteLine("Expected ack number: " + _expectedAckNumber);
                    Console.WriteLine("Received ack number: " + packet.Ethernet.IpV4.Tcp.AcknowledgmentNumber);
                    if (packet.Ethernet.IpV4.Tcp.AcknowledgmentNumber == _expectedAckNumber)
                    {
                        break;
                    }

                }
                SendGet(communicator);
            }
            */

            return new MacAddress("02:02:02:02:02:02");
        }
    }
}
