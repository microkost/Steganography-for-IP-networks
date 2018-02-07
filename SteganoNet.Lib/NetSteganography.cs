using System;
using System.Collections.Generic;
using System.Linq;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Icmp;
using PcapDotNet.Packets.IpV4;

namespace SteganoNetLib
{
    public static class NetSteganography //not static
    {
        //private readonly Dictionary<int, string> listOfStegoMethods;

        /*
        public NetSteganography(List<int> listOfMethodIndexes)
        {
             listOfStegoMethods = NetSteganography.GetListOfStegoMethods();
        }
        */

        public static Dictionary<int, string> GetListOfStegoMethods()
        {
            /* 
             * Logic of ID integers: (do not use xx0, keep them like group name)
             * 0xx > debug & developer
             * 1xx > physical layer
             * 2xx > data-link layer
             * 3xx > network layer 
             * 4xx > transport layer 
             * 7xx > session, presentation and application layer
             * 8xx > other methods like time channel
             */

            Dictionary<int, string> listOfStegoMethods = new Dictionary<int, string>();
            listOfStegoMethods.Add(301, "IP (Type of service)");
            listOfStegoMethods.Add(302, "IP (Identification)");
            listOfStegoMethods.Add(303, "IP (Flags)");
            listOfStegoMethods.Add(331, "ICMP (Identifier)");
            listOfStegoMethods.Add(332, "ICMP (Sequence number)");

            //IP method 1 - most transparent - using Identification field and changing it every two minutes accoring to standard - iteration of value 
            //IP method X - offset number like TTL lower, smth constant is under or value is unmasked... IF allowed!
            //IP method 2 - maximum method (method 1 + usage of flags + fragment offset + 
            //ip method 3 - transparent - count TTL and use some value under as rest...
            //IP method 4 - TypeOfService fild - extrely lame way but... Usage high bits 6 + 7 is "OK"...
            //IP method 5  - 

            return listOfStegoMethods; //DO NOT MODIFY THAT LIST DURING RUNNING
        }

        public static List<int> GetListMethodIds(int startValue, int endValue, List<int> source) //returns ids of methods from certain range when source specified
        {
            if (source == null)
            {
                source = GetListOfStegoMethods().Keys.ToList(); //TODO test
            }

            IEnumerable<int> listOfIpMethods = from num in source where num >= startValue && num <= endValue select num;
            return listOfIpMethods.ToList();
        }

        //ip layer methods
        public static string GetContent3Network(IpV4Datagram ip, List<int> stegoUsedMethodIds, NetReceiverServer rsForInfoMessages = null)
        {
            List<string> LocalMethodMessages = new List<string>();
            List<string> BlocksOfSecret = new List<string>();

            if (ip == null) { return null; } //extra protection

            foreach (int methodId in stegoUsedMethodIds) //process every method separately on this packet
            {
                LocalMethodMessages.Add("3IP: method " + methodId);
                switch (methodId)
                {
                    case 301: //IP (Type of service)
                        {
                            string binvalue = Convert.ToString(ip.TypeOfService, 2);
                            BlocksOfSecret.Add(binvalue.PadLeft(16, '0')); //when zeros was cutted
                            break;
                        }
                    case 302: //IP (Identification)
                        {
                            string binvalue = Convert.ToString(ip.Identification, 2);
                            //TODO, only in first packet!
                            BlocksOfSecret.Add(binvalue.PadLeft(16, '0')); //when zeros was cutted
                            break;
                        }
                    case 331: //ICMP (Identifier)
                        {
                            IcmpIdentifiedDatagram icmp = (ip.Icmp.IsValid == true) ? (IcmpIdentifiedDatagram)ip.Icmp : null; //parsing layer for processing            
                            if (icmp.IsValid != true)
                                continue;

                            string binvalue = Convert.ToString(icmp.Identifier, 2);
                            BlocksOfSecret.Add(binvalue.PadLeft(16, '0')); //when zeros was cutted

                            break;
                        }
                    case 332: //ICMP (Sequence number)
                        {
                            IcmpIdentifiedDatagram icmp = (ip.Icmp.IsValid == true) ? (IcmpIdentifiedDatagram)ip.Icmp : null; //parsing layer for processing            
                            if (icmp.IsValid != true)
                                continue;

                            //todo

                            break;
                        }
                }
            }


            if (rsForInfoMessages != null) //providint user friendly debug output to console
            {
                foreach (string localMessageToGlobal in LocalMethodMessages)
                {
                    rsForInfoMessages.AddInfoMessage(localMessageToGlobal);
                }

            }

            if (BlocksOfSecret.Count <= 0) //providing value output
            {
                return string.Join("", BlocksOfSecret.ToArray());
            }
            else
            {
                return "error"; //null
            }
        }


        //tcp layer methods

        //udp layer methods - skipped by assigment

        //application layer methods

        public static bool Reply3Network(Packet packet)
        {

            return false;
        }


    }
}
