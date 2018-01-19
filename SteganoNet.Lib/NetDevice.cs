using PcapDotNet.Core;
using PcapDotNet.Packets.IpV4;
using System;
using System.Collections.Generic;

namespace SteganoNetLib
{
    public static class NetDevice
    {
        //general
        public static IList<LivePacketDevice> allDevices = LivePacketDevice.AllLocalMachine; //list of available devices               

        public static PacketDevice GetSelectedDevice(IpV4Address ipOfInterface)
        {           
            string tmpIp = ipOfInterface.ToString(); //nessesary for lookup method below

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

                    if (String.Equals(words[2], tmpIp)) //should be more effective by filtering IPv6 out
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
                deviceIndex = 0; //TODO better! It is confusing when is any problem in code...
            }

            return NetDevice.allDevices[deviceIndex];            
        }

        //L2
        //NetStandard

        //L3
        public static List<string> GetIPv4addressesLocal() //return available list of IP addresses
        {
            List<String> result = new List<String>(); //TODO should be List<IpV4Address>
            //result.Add("127.0.0.1"); //TODO add localhost

            foreach (LivePacketDevice lpd in allDevices)
            {
                foreach (DeviceAddress nonparsed in lpd.Addresses) //try-catch needed?
                {
                    string tmp = nonparsed.ToString();
                    string[] words = tmp.Split(' '); //string: Address: Internet 192.168.124.1 Netmask: Internet 255.255.255.0 Broadcast: Internet 0.0.0.0

                    if (words[1] == "Internet6")
                    {
                        //print String.Format("IPv6 skipped\r\n");
                    }

                    if (words[1] == "Internet")
                    {
                        result.Add(words[2]);                        
                    }
                }
            }

            return result;
        }


    }
}
