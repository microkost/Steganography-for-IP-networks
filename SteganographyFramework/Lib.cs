using System;
using System.Collections.Generic;
using PcapDotNet.Core;
using PcapDotNet.Packets.IpV4;

namespace SteganographyFramework
{
    public static class Lib
    {
        public static List<String> listOfStegoMethods = new List<String>() { "ICMP", "TCP", "IP", "ISN + IP ID", "DNS" }; //List of methods used in code and GUI, index of method is important!

        public static IList<LivePacketDevice> allDevices = LivePacketDevice.AllLocalMachine; //list of available devices       

        public static PacketDevice selectedDevice; //which device will be used for communication
        public static int getSelectedInterfaceIndex(IpV4Address ipToIndex) //returns index of selected interface to be selected for communication
        {
            //exceptions when allDevices are not initialized! Missing protection!

            string tmpIp = ipToIndex.ToString(); //nessesary for lookup method below

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

            if (allDevices.Count <= i) 
            {
                deviceIndex = 0; //TODO better! Is confusing when is any problem in function!
            }

            return (deviceIndex);
        }
        public static bool checkPrerequisites() //unfinished
        {
            //not finished! used on GUI level

            if (allDevices == null)
                return false;

            if (allDevices.Count == 0)
                return false;

            return true;
        }
        public static uint getSynOrAckRandNumber() //for generating random SYN and ACK numbers
        {
            //effectively random; it may be any value between 0 and 4,294,967,295, inclusive. 
            return 20710000;
        }
    }
}
