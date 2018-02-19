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
        //magic numbers dialer
        public const int IpRangeStart = 300;
        public const int IpRangeEnd = 399;
        
        public static Dictionary<int, string> GetListStegoMethodsIdAndKey() //service method
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

            Dictionary<int, string> listOfStegoMethods = new Dictionary<int, string>
            {
                { 301, "IP (Type of service)" },
                { 302, "IP (Identification)" },
                { 303, "IP (Flags)" },
                { 331, "ICMP (Identifier)" },
                { 332, "ICMP (Sequence number)" }
            };

            //IP method 1 - most transparent - using Identification field and changing it every two minutes accoring to standard - iteration of value 
            //IP method X - offset number like TTL lower, smth constant is under or value is unmasked... IF allowed!
            //IP method 2 - maximum method (method 1 + usage of flags + fragment offset + 
            //ip method 3 - transparent - count TTL and use some value under as rest...
            //IP method 4 - TypeOfService fild - extrely lame way but... Usage high bits 6 + 7 is "OK"...
            //IP method 5  - 

            return listOfStegoMethods; //DO NOT MODIFY THAT LIST DURING RUNNING
        }

        //service method
        public static List<int> GetListMethodsId(int startValue, int endValue, Dictionary<int, string> stegoMethodsIdAndKey) //returns ids of methods from certain range when source specified
        {
            List<int> source = stegoMethodsIdAndKey.Keys.ToList(); //separate ids from dictionary

            if (source == null)
            {
                source = GetListStegoMethodsIdAndKey().Keys.ToList(); //TODO test, is dangerous when no list in GetListStegoMethodsIdAndKey
            }

            IEnumerable<int> listOfIpMethods = from num in source where num >= startValue && num <= endValue select num;
            return listOfIpMethods.ToList();
        }

        //---------------------------------------------------------------------------------------------------------------------

        //ip layer methods
        public static string GetContent3Network(IpV4Datagram ip, List<int> stegoUsedMethodIds, NetReceiverServer rs = null)
        {
            //List<string> LocalMethodMessages = new List<string>();
            List<string> BlocksOfSecret = new List<string>();

            if (ip == null) { return null; } //extra protection

            foreach (int methodId in stegoUsedMethodIds) //process every method separately on this packet
            {
                rs.AddInfoMessage("3IP: method " + methodId);
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

            if (BlocksOfSecret.Count != 0) //providing value output
            {
                return string.Join("", BlocksOfSecret.ToArray()); //joining binary substring
            }
            else
            {
                return "error"; //null
            }
        }

        public static Tuple<IpV4Layer, string> SetContent3Network(IpV4Layer ip, List<int> stegoUsedMethodIds, string secret, NetSenderClient sc = null)
        {
            if (ip == null)
                return null;
            
            sc.AddInfoMessage("SetContent3Network UNIMPLEMENTED!");

            //TODO implement

            string insertedtext = "";
            

            return new Tuple<IpV4Layer, string>(ip, insertedtext);
        }

        //tcp layer methods

        //udp layer methods - skipped by assigment

        //application layer methods
    }
}
