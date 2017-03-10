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

namespace RawSocket
{
    public static class Lib
    {
        public static IList<LivePacketDevice> allDevices = LivePacketDevice.AllLocalMachine; //list of available devices

        public static List<String> listOfStegoMethods = new List<String>() { "ICMP cosik", "neco dalsiho" };

        public static PacketDevice selectedDevice; //which device will be used for communication
        public static int getSelectedInterfaceIndex(string tmpIp) //returns index of selected interface to be selected for communication
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

            if (allDevices.Count < i) //todo better!
            {
                deviceIndex = 0;
                //SettextBoxDebug(String.Format("Error in selecting interface, choosing the first.\r\n"));
            }

            return (deviceIndex);
        }

        public static bool checkPrerequisites()
        {
            if (allDevices == null)
                return false;

            if (allDevices.Count == 0)
                return false;
                //SettextBoxDebug("No interfaces found! Make sure WinPcap is installed.\n");

            return true;
        }

        public string
    }
}
