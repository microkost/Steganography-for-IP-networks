using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using PcapDotNet.Packets.Icmp;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.Transport;

namespace SteganoNetLib
{
    public static class NetSteganography //not static
    {
        //magic numbers dialer (never use numbers directly outside this class, if needed use like "IcmpGenericPing" value)
        public const int IpRangeStart = 300;
        public const int IpRangeEnd = 329;
        public const int IcmpRangeStart = 330;
        public const int IcmpRangeEnd = 359;
        public const int IcmpGenericPing = 331;
        public const int NetworkRangeStart = IpRangeStart;
        public const int NetworkRangeEnd = 399;
        //udp
        public const int TcpRangeStart = 450;
        public const int TcpRangeEnd = 499;

        private static Random rand = new Random();
        private static ushort SequenceNumber = (ushort)DateTime.Now.Ticks; //for legacy usage        

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

            //for details read file MethodDescription.txt, keep it updated if changing following list!
            Dictionary<int, string> listOfStegoMethods = new Dictionary<int, string>
            {
                // { 000, "Nothing, pure" },
                { 301, "IP (Type of service / DiffServ agresive) - 8b" },
                { 302, "IP (Type of service / DiffServ) - 2b" },
                { 303, "IP (Identification)" }, //TODO
                { 305, "IP (Flags)" }, //TODO
                { 331, "ICMP ping (Standard, for other layers) - 0b" },
                { 333, "ICMP ping (Identifier) - 16b" },
                { 335, "ICMP ping (Sequence number) - 16b" },
                { 337, "ICMP ping (Data field) - up to MTU" }, //TODO
                { 451, "TCP (standard) - 0b" } //TODO
            };

            //IP method 1 - most transparent - using Identification field and changing it every two minutes accoring to standard - iteration of value 
            //IP method X - offset number like TTL lower, smth constant is under or value is unmasked... IF allowed!
            //IP method 2 - maximum method (method 1 + usage of flags + fragment offset + 
            //ip method 3 - transparent - count TTL and use some value under as rest...
            //IP method 4 - TypeOfService fild - extrely lame way but... Usage high bits 6 + 7 is "OK"...
            //IP method 5  - 

            //ttl methods, resting value is magic value, round trip timer
            //ping delay or TCP delay

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
        public static Tuple<IpV4Layer, string> SetContent3Network(IpV4Layer ip, List<int> stegoUsedMethodIds, string secret, NetSenderClient sc = null) //SENDER
        {
            if (ip == null) { return null; } //extra protection
            Stopwatch sw = new Stopwatch(); //for timeout

            foreach (int methodId in stegoUsedMethodIds) //process every method separately on this packet
            {
                sc.AddInfoMessage("3IP: method " + methodId);

                switch (methodId)
                {
                    case 301: //IP (Type of service / DiffServ) //SENDER
                        {
                            const int usedbits = 8;
                            try
                            {
                                string partOfSecret = secret.Remove(usedbits, secret.Length - usedbits);
                                //sc.AddInfoMessage("S> " + methodId + " : " + partOfSecret);
                                ip.TypeOfService = Convert.ToByte(partOfSecret, 2); //using 8 bits                                
                                secret = secret.Remove(0, usedbits);
                            }
                            catch
                            {
                                if (secret.Length != 0)
                                {
                                    ip.TypeOfService = Convert.ToByte(secret.PadLeft(usedbits, '0'), 2); //using rest + padding
                                    //sc.AddInfoMessage("S> " + methodId + " : " + secret + " alias " + secret.PadLeft(usedbits, '0'));
                                    secret = secret.Remove(0, secret.Length);
                                }
                                return new Tuple<IpV4Layer, string>(ip, secret); //nothing more                               
                            }
                            break;
                        }
                    case 302: //IP (Type of service / DiffServ) //SENDER
                        {
                            const int usedbits = 2;
                            try
                            {
                                string partOfSecret = secret.Remove(usedbits, secret.Length - usedbits);
                                //sc.AddInfoMessage(">> " + methodId + " : " + partOfSecret);
                                ip.TypeOfService = Convert.ToByte(partOfSecret, 2);
                                secret = secret.Remove(0, usedbits);
                            }
                            catch
                            {
                                if (secret.Length != 0)
                                {
                                    ip.TypeOfService = Convert.ToByte(secret.PadLeft(usedbits, '0'), 2); //using rest + padding
                                    //sc.AddInfoMessage(">> " + methodId + " : " + secret + " alias " + secret.PadLeft(usedbits, '0'));
                                    secret = secret.Remove(0, secret.Length);
                                }
                                return new Tuple<IpV4Layer, string>(ip, secret); //nothing more          
                            }
                            break;
                        }
                    case 303: //IP (Identification) //SENDER
                        {                            
                            sw.Start();
                            const int usedbits = 16;                         
                            //first run start timer, add value to output and save it outside loop. Replace value and send new one after timer expire.
                            try
                            {
                                string partOfSecret = secret.Remove(usedbits, secret.Length - usedbits);
                                //set * Non-atomic datagrams: (DF==0)||(MF==1)||(frag_offset>0)
                                ip.Identification = Convert.ToByte(partOfSecret, 2);
                                secret = secret.Remove(0, usedbits);

                                //after first is leave
                                if (sw.ElapsedMilliseconds < 120000) //timeout break twoMinInMs
                                {
                                    break;
                                }
                                else
                                {
                                    sw.Stop();
                                    sw.Reset();
                                }
                            }
                            catch
                            {
                                if (secret.Length != 0)
                                {
                                    ip.Identification = Convert.ToByte(secret.PadLeft(usedbits, '0'), 2); //using rest + padding
                                    secret = secret.Remove(0, secret.Length);
                                }
                                return new Tuple<IpV4Layer, string>(ip, secret); //nothing more          
                            }
                            break;
                        }
                    case 305: //IP Flags...
                        {
                            /* In IPv4, fragments are indicated using four fields of the basic header: 
                             * Identification(ID), Fragment Offset, a "Don't Fragment" (DF) flag, and a "More Fragments"(MF) flag
                             */
                            break;
                        }
                }
            }

            return new Tuple<IpV4Layer, string>(ip, secret);
        }
        public static string GetContent3Network(IpV4Datagram ip, List<int> stegoUsedMethodIds, NetReceiverServer rs = null) //RECEIVER
        {
            if (ip == null) { return null; } //extra protection
            List<string> BlocksOfSecret = new List<string>();

            foreach (int methodId in stegoUsedMethodIds) //process every method separately on this packet
            {
                rs.AddInfoMessage("3IP: method " + methodId); //add number of received bits in this iteration
                switch (methodId)
                {
                    case 301: //IP (Type of service / DiffServ agresive) RECEIVER
                        {
                            string binvalue = Convert.ToString(ip.TypeOfService, 2); //use whole field
                            string binvaluePadded = binvalue.PadLeft(8, '0');
                            BlocksOfSecret.Add(binvaluePadded); //when zeros was cutted
                            break;
                        }
                    case 302: //IP (Type of service / DiffServ) RECEIVER
                        {
                            string fullfield = Convert.ToString(ip.TypeOfService, 2).PadLeft(8, '0');
                            string binvalue = fullfield.Substring(fullfield.Length - 2); //use only last two bits
                            BlocksOfSecret.Add(binvalue);
                            break;
                        }
                    case 303: //IP (Identification) RECEIVER
                        {
                            //TODO, only in first packet or change it every two minutes
                            //SENDER NOT DONE
                            string binvalue = Convert.ToString(ip.Identification, 2);
                            BlocksOfSecret.Add(binvalue.PadLeft(16, '0')); //when zeros was cutted
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
                return null;
            }
        }

        //icmp layer methods
        public static Tuple<IcmpEchoLayer, string> SetContent3Icmp(IcmpEchoLayer icmp, List<int> stegoUsedMethodIds, string secret, NetSenderClient sc = null)
        {
            if (icmp == null) { return null; } //extra protection            

            foreach (int methodId in stegoUsedMethodIds) //process every method separately on this packet
            {
                sc.AddInfoMessage("3IP: method " + methodId);

                switch (methodId)
                {
                    case IcmpGenericPing: //ICMP (standard, for other layers) //SENDER (alias 331, but value used in code)
                        {
                            icmp.SequenceNumber = SequenceNumber++; //legacy sequence number
                            icmp.Identifier = (ushort)rand.Next(0, 65535);
                            //add delay 1000 miliseconds on parent object
                            break;
                        }
                    case 333: //ICMP (Identifier) //SENDER
                        {
                            if (!stegoUsedMethodIds.Contains(335)) //do not overwrite sequence number when that method selected
                            {
                                icmp.SequenceNumber = SequenceNumber++; //legacy sequence number
                            }

                            const int usedbits = 16;
                            try
                            {
                                string partOfSecret = secret.Remove(usedbits, secret.Length - usedbits);
                                icmp.Identifier = Convert.ToUInt16(partOfSecret, 2);
                                secret = secret.Remove(0, usedbits);
                            }
                            catch
                            {
                                if (secret.Length != 0)
                                {
                                    icmp.Identifier = Convert.ToByte(secret.PadLeft(usedbits, '0'), 2); //using rest + padding
                                    secret = secret.Remove(0, secret.Length);
                                }
                                return new Tuple<IcmpEchoLayer, string>(icmp, secret); //nothing more                               
                            }
                            break;
                        }
                    case 335: //ICMP (Sequence number) //SENDER
                        {
                            if (!stegoUsedMethodIds.Contains(333)) //do not overwrite identifier when that method selected
                            {
                                icmp.Identifier = icmp.Identifier = (ushort)rand.Next(0, 65535); //legacy Identifier number
                            }

                            const int usedbits = 16;
                            try
                            {
                                string partOfSecret = secret.Remove(usedbits, secret.Length - usedbits);
                                icmp.SequenceNumber = Convert.ToUInt16(partOfSecret, 2);
                                secret = secret.Remove(0, usedbits);
                            }
                            catch
                            {
                                if (secret.Length != 0)
                                {
                                    icmp.SequenceNumber = Convert.ToByte(secret.PadLeft(usedbits, '0'), 2); //using rest + padding
                                    secret = secret.Remove(0, secret.Length);
                                }
                                return new Tuple<IcmpEchoLayer, string>(icmp, secret); //nothing more                               
                            }
                            break;
                        }
                        //case 337: icmp.Payload = "";
                }
            }

            return new Tuple<IcmpEchoLayer, string>(icmp, secret);
        }

        public static string GetContent3Icmp(IcmpEchoDatagram icmp, List<int> stegoUsedMethodIds, NetReceiverServer rs = null) //RECEIVER
        {
            if (icmp == null) { return null; } //extra protection
            List<string> BlocksOfSecret = new List<string>();

            foreach (int methodId in stegoUsedMethodIds) //process every method separately on this packet
            {
                rs.AddInfoMessage("3ICMP: method " + methodId); //add number of received bits in this iteration
                switch (methodId)
                {
                    case 331: //ICMP (pure) RECEIVER
                        {
                            //no stehanography included - OK
                            break;
                        }
                    case 333: //ICMP (Identifier) RECEIVER
                        {
                            string binvalue = Convert.ToString(icmp.Identifier, 2);
                            BlocksOfSecret.Add(binvalue.PadLeft(16, '0')); //when zeros was cutted
                            break;
                        }
                    case 335: //ICMP (Sequence number) RECEIVER
                        {
                            string binvalue = Convert.ToString(icmp.SequenceNumber, 2);
                            BlocksOfSecret.Add(binvalue.PadLeft(16, '0')); //when zeros was cutted
                            break;
                        }
                        //case 337: icmp.Payload = "";
                }
            }

            if (BlocksOfSecret.Count != 0) //providing value output
            {
                return string.Join("", BlocksOfSecret.ToArray()); //joining binary substring
            }
            else
            {
                return null;
            }
        }


        //-L4------------------------------------------------------------------------------------------------------------------

        //udp layer methods - skipped by assigment

        //tcp layer methods

        public static Tuple<TcpLayer, string> SetContent4Tcp(TcpLayer tcp, List<int> stegoUsedMethodIds, string secret, NetSenderClient sc = null)
        {
            if (tcp == null) { return null; } //extra protection

            foreach (int methodId in stegoUsedMethodIds) //process every method separately on this packet
            {
                sc.AddInfoMessage("4TCP: method " + methodId);

                //needs to handle states
                //SYN
                //SYN+ACK
                //ACK

                switch (methodId)
                {
                    case 451: //ICMP (standard, for other layers) //SENDER (alias 331, but value used in code)
                        {

                            break;
                        }
                }
            }

            return new Tuple<TcpLayer, string>(tcp, secret);
        }

        //get content

        //-L5---L7-------------------------------------------------------------------------------------------------------------

        //application layer methods
    }
}
