using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using PcapDotNet.Packets.Dns;
using PcapDotNet.Packets.Http;
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
        public const int IpIdentificationMethod = 303;

        public const int IcmpRangeStart = 330;
        public const int IcmpRangeEnd = 359;
        public const int IcmpGenericPing = 331;

        public const int NetworkRangeStart = IpRangeStart; //used in test
        public const int NetworkRangeEnd = 399; //used in test
        //udp
        public const int TcpRangeStart = 450;
        public const int TcpRangeEnd = 499;

        public const int DnsRangeStart = 700;
        public const int DnsRangeEnd = 729;

        public const int HttpRangeStart = 730;
        public const int HttpRangeEnd = 759;

        private static Random rand = new Random();
        private static ushort SequenceNumber = (ushort)DateTime.Now.Ticks; //for legacy usage        
        private static string Identification = ""; //receiver's holding value place

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
             * 
             * dash '-' is splitter for parsing capacity size of method! Always at the end with size and unit ' - 100b' for 100 bits in method
             * inform user about settings in [] brackets like exact delay if possible (constants)
             */

            //for details read file MethodDescription.txt, keep it updated if changing following list!
            Dictionary<int, string> listOfStegoMethods = new Dictionary<int, string>
            {
                { 301, "IP Type of service / DiffServ (agresive) - 8b" },
                { 302, "IP Type of service / DiffServ - 2b" },
                { 303, String.Format("IP Identification [delay {0} s] - 16b", (double)NetSenderClient.IpIdentificationChangeSpeedInMs/1000) }, //adding exact time value to the name

                { 331, String.Format("ICMP ping (standard) [delay {0} s] - 0b", (double)NetSenderClient.delayIcmp/1000) },
                { 333, "ICMP ping (Identifier) - 16b" },
                { 335, "ICMP ping (Sequence number) - 16b" },
                //case 337: icmp.Payload = "";               

                { 451, "TCP (standard) - 0b" }, //TODO
                //{ 453, "TCP (ISN) - 32b" }, //TODO

                { 701, String.Format("DNS request (standard) [delay {0} s] - 0b", (double)NetSenderClient.delayDns/1000) },
                { 703, "DNS request (transaction id) - 16b" },

                { 731, "HTTP request () - 16b" } //TODO

                //HTTP Entity tag headers 
                //HTTP 7

                //pspping principe
                
                //TODO time channel! (ttl methods, resting value is magic value, round trip timer) (ping delay or TCP delay)
                //TODO TTL usage or similar (count TTL and use some value under as rest...)
            };

            return listOfStegoMethods; //DO NOT DYNAMICAL MODIFY THAT LIST DURING RUNNING
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

        public static Dictionary<int, int> GetMethodsCapacity()
        {
            //TODO
            //get list of all methods
            //parse their names by symbol "-" to keep just values
            //merge it with id to dictionary key
            return null;
        }

        //---------------------------------------------------------------------------------------------------------------------

        //ip layer methods               
        public static Tuple<IpV4Layer, string> SetContent3Network(IpV4Layer ip, List<int> stegoUsedMethodIds, string secret, NetSenderClient sc = null, bool firstAndResetRun = false) //SENDER
        {
            if (ip == null) { return null; } //extra protection

            foreach (int methodId in stegoUsedMethodIds) //process every method separately on this packet
            {
                switch (methodId)
                {
                    case 301: //IP (Type of service / DiffServ) //SENDER
                        {
                            sc.AddInfoMessage("3IP: method " + methodId);
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
                            sc.AddInfoMessage("3IP: method " + methodId);
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
                            //sc.AddInfoMessage("3IP: method " + methodId);                            
                            const int usedbits = 16;
                            if (firstAndResetRun == true)
                            {
                                sc.AddInfoMessage("3IP: method " + methodId + " it's first or reseted run");
                                try
                                {
                                    string partOfSecret = secret.Remove(usedbits, secret.Length - usedbits);
                                    //set * Non-atomic datagrams: (DF==0)||(MF==1)||(frag_offset>0)
                                    //Fragmentation = IpV4Fragmentation.None, //new IpV4Fragmentation(IpV4FragmentationOptions.DoNotFragment, 0),
                                    //TODO ADD FLAGS
                                    ip.Identification = Convert.ToUInt16(partOfSecret, 2);
                                    secret = secret.Remove(0, usedbits);
                                }
                                catch
                                {
                                    if (secret.Length != 0)
                                    {
                                        ip.Identification = Convert.ToUInt16(secret.PadLeft(usedbits, '0'), 2); //using rest + padding
                                        secret = secret.Remove(0, secret.Length);
                                    }
                                    return new Tuple<IpV4Layer, string>(ip, secret); //nothing more          
                                }
                            }
                            break;
                        }
                    case 305: //IP Flags...
                        {
                            sc.AddInfoMessage("3IP: method " + methodId);
                            /* In IPv4, fragments are indicated using four fields of the basic header: 
                             * Fragment Offset, a "Don't Fragment" (DF) flag, and a "More Fragments"(MF) flag
                             * Fragmentation = IpV4Fragmentation.None, //new IpV4Fragmentation(IpV4FragmentationOptions.DoNotFragment, 0),
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
                switch (methodId)
                {
                    case 301: //IP (Type of service / DiffServ agresive) RECEIVER
                        {
                            rs.AddInfoMessage("3IP: method " + methodId); //add number of received bits in this iteration
                            string binvalue = Convert.ToString(ip.TypeOfService, 2); //use whole field
                            string binvaluePadded = binvalue.PadLeft(8, '0');
                            BlocksOfSecret.Add(binvaluePadded); //when zeros was cutted
                            break;
                        }
                    case 302: //IP (Type of service / DiffServ) RECEIVER
                        {
                            rs.AddInfoMessage("3IP: method " + methodId); //add number of received bits in this iteration
                            string fullfield = Convert.ToString(ip.TypeOfService, 2).PadLeft(8, '0');
                            string binvalue = fullfield.Substring(fullfield.Length - 2); //use only last two bits
                            BlocksOfSecret.Add(binvalue);
                            break;
                        }
                    case 303: //IP (Identification) RECEIVER
                        {
                            rs.AddInfoMessage("3IP: method " + methodId); //add number of received bits in this iteration

                            string binvalue = Convert.ToString(ip.Identification, 2);
                            if (Identification != binvalue) //do not add value when it didnt change
                            {
                                Identification = binvalue;
                                BlocksOfSecret.Add(binvalue.PadLeft(16, '0')); //when zeros was cutted    
                            }
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
                switch (methodId)
                {
                    case IcmpGenericPing: //ICMP (standard, for other layers) //SENDER (alias 331, but value used in code)
                        {
                            sc.AddInfoMessage("3ICMP: method " + methodId);
                            icmp.SequenceNumber = SequenceNumber++; //legacy sequence number
                            icmp.Identifier = (ushort)rand.Next(0, 65535);
                            //add delay 1000 miliseconds on parent object
                            break;
                        }
                    case 333: //ICMP (Identifier) //SENDER
                        {
                            sc.AddInfoMessage("3ICMP: method " + methodId);
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
                                    icmp.Identifier = Convert.ToUInt16(secret.PadLeft(usedbits, '0'), 2); //using rest + padding
                                    secret = secret.Remove(0, secret.Length);
                                }
                                return new Tuple<IcmpEchoLayer, string>(icmp, secret); //nothing more                               
                            }
                            break;
                        }
                    case 335: //ICMP (Sequence number) //SENDER
                        {
                            sc.AddInfoMessage("3ICMP: method " + methodId);
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
                                    icmp.SequenceNumber = Convert.ToUInt16(secret.PadLeft(usedbits, '0'), 2); //using rest + padding
                                    secret = secret.Remove(0, secret.Length);
                                }
                                return new Tuple<IcmpEchoLayer, string>(icmp, secret); //nothing more                               
                            }
                            break;
                        }
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
                switch (methodId)
                {
                    case IcmpGenericPing: //ICMP (pure) RECEIVER
                        {
                            rs.AddInfoMessage("3ICMP: method " + methodId + " (no stehanography included)"); //add number of received bits in this iteration
                            break;
                        }
                    case 333: //ICMP (Identifier) RECEIVER
                        {
                            rs.AddInfoMessage("3ICMP: method " + methodId);
                            string binvalue = Convert.ToString(icmp.Identifier, 2);
                            BlocksOfSecret.Add(binvalue.PadLeft(16, '0')); //when zeros was cutted
                            break;
                        }
                    case 335: //ICMP (Sequence number) RECEIVER
                        {
                            rs.AddInfoMessage("3ICMP: method " + methodId);
                            string binvalue = Convert.ToString(icmp.SequenceNumber, 2);
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

        //-L4------------------------------------------------------------------------------------------------------------------

        //udp layer methods - skipped

        //TCP layer methods
        public static Tuple<TcpLayer, string> SetContent4Tcp(TcpLayer tcp, List<int> stegoUsedMethodIds, string secret, NetSenderClient sc = null)
        {
            if (tcp == null) { return null; } //extra protection

            foreach (int methodId in stegoUsedMethodIds) //process every method separately on this packet
            {
                //needs to handle states of TCP to read only from proper state like SYN, SYNACK

                switch (methodId)
                {
                    case 451: //TCP (standard, for other layers) //SENDER
                        {
                            sc.AddInfoMessage("4TCP: method " + methodId);
                            break;
                        }
                }
            }

            return new Tuple<TcpLayer, string>(tcp, secret);
        }

        //TODO GetContent4Tcp

        //-L5-to-L7------------------------------------------------------------------------------------------------------------

        public static Tuple<DnsLayer, string> SetContent7Dns(DnsLayer dns, List<int> stegoUsedMethodIds, string secret, NetSenderClient sc = null) //SENDER
        {
            if (dns == null) { return null; } //extra protection

            foreach (int methodId in stegoUsedMethodIds) //process every method separately on this packet
            {
                switch (methodId)
                {
                    case 701: //DNS clean //SENDER
                        {
                            sc.AddInfoMessage("7DNS: legacy method " + methodId + " (no data removed)");
                            dns.Id = (ushort)rand.Next(0, 65535);
                            break;
                        }
                    case 703: //DNS (transaction id) //SENDER
                        {
                            sc.AddInfoMessage("7DNS: method " + methodId);
                            const int usedbits = 16;
                            try
                            {
                                string partOfSecret = secret.Remove(usedbits, secret.Length - usedbits);
                                dns.Id = Convert.ToUInt16(partOfSecret, 2);
                                secret = secret.Remove(0, usedbits);
                            }
                            catch
                            {
                                if (secret.Length != 0)
                                {
                                    dns.Id = Convert.ToUInt16(secret.PadLeft(usedbits, '0'), 2); //using rest + padding
                                    secret = secret.Remove(0, secret.Length);
                                }
                                return new Tuple<DnsLayer, string>(dns, secret); //nothing more          
                            }
                            break;
                        }
                }
            }
            return new Tuple<DnsLayer, string>(dns, secret);
        }

        public static string GetContent7Dns(DnsDatagram dns, List<int> stegoUsedMethodIds, NetReceiverServer rs = null) //RECEIVER
        {
            if (dns == null) { return null; } //extra protection
            List<string> BlocksOfSecret = new List<string>();

            foreach (int methodId in stegoUsedMethodIds) //process every method separately on this packet
            {
                switch (methodId)
                {
                    case 701: //DNS (pure) RECEIVER
                        {
                            rs.AddInfoMessage("7DNS: method " + methodId + " (no stehanography included)");
                            break;
                        }
                    case 703: //DNS (Id) RECEIVER
                        {
                            rs.AddInfoMessage("7DNS: method " + methodId);
                            string binvalue = Convert.ToString(dns.Id, 2);
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


        //SetContent7Http

        public static string GetContent7Http(HttpDatagram http, List<int> stegoUsedMethodIds, NetReceiverServer rs = null)
        {
            if (http == null) { return null; } //extra protection
            List<string> BlocksOfSecret = new List<string>();

            foreach (int methodId in stegoUsedMethodIds) //process every method separately on this packet
            {
                switch (methodId)
                {
                    case 731: //HTTP (pure) RECEIVER
                        {
                            rs.AddInfoMessage("7HTTP: method " + methodId + " (no stehanography included)"); //add number of received bits in this iteration
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
    }
}

