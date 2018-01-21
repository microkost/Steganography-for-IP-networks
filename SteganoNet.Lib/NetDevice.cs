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
                 
            foreach (LivePacketDevice lpd in allDevices)
            {                
                foreach (DeviceAddress nonparsed in lpd.Addresses)
                {                    
                    string[] words = nonparsed.ToString().Split(' ');

                    if (String.Equals(words[2], tmpIp)) //should be more effective by filtering IPv6 out
                    {
                        return lpd; //return device with requested IP
                    }
                }
            }

            return null; //can be easily tested
            //return NetDevice.allDevices[0]; //working but very tricky
        }

        //L2        

        //L3
        public static List<Tuple<string, string>> GetIPv4addressesAndDescriptionLocal() //pair of strings ipv4 and description for UI
        {
            List<Tuple<string, string>> result = new List<Tuple<string, string>>();
            foreach(string ipv4add in GetIPv4addressesLocal()) //get list of local IPv4 addresses from other method
            {
                PacketDevice pd = GetSelectedDevice(new IpV4Address(ipv4add));
                if(pd == null)
                    continue; //test //TODO ternary...

                result.Add(new Tuple<string, string>(ipv4add, pd.Description));
            }
            return result;
        }

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

        //L4

        //L7

    }
}
