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
using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Net;
using System.Runtime.InteropServices;

namespace SteganographyFramework
{
    public static class Lib
    {
        public static List<String> listOfStegoMethods = new List<String>() { "ICMP", "TCP", "IP", "ISN + IP ID", "DNS" }; //List of methods used in code and GUI, index of method is important!

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
                    break;

                foreach (DeviceAddress nonparsed in lpd.Addresses)
                {
                    string tmp = nonparsed.ToString();
                    string[] words = tmp.Split(' ');

                    if (String.Equals(words[2], tmpIp)) //should be more effective by filtering IPv6
                    {
                        deviceIndex = i;
                        exit = true;
                        break;
                    }
                    else
                    {
                        i++;
                    }
                }
            }

            if (allDevices.Count <= i) //TODO better
            {
                deviceIndex = 0;
            }

            return (deviceIndex);
        }
        public static bool checkPrerequisites()
        {
            //not finished! used on GUI level

            if (allDevices == null)
                return false;

            if (allDevices.Count == 0)
                return false;

            return true;
        }
    }
}
