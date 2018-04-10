using System;
using System.Collections.Generic;
using System.Linq;
using PcapDotNet.Packets.Dns;
using PcapDotNet.Packets.Http;
using PcapDotNet.Packets.Icmp;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.Transport;

namespace SteganoNetLib
{
    public static class NetSteganography
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
        public const int TcpRangeStart = 450;
        public const int TcpRangeEnd = 499;
        public const int DnsRangeStart = 700;
        public const int DnsRangeEnd = 729;
        public const int HttpRangeStart = 730;
        public const int HttpRangeEnd = 759;

        //internal value holders
        private static Random rand = new Random();
        private static ushort SequenceNumberICMP = (ushort)DateTime.Now.Ticks; //for legacy usage        
        private static string IdentificationIP = ""; //receiver's holding value place
        private static string IdentificationTCP = ""; //receiver's holding value place

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
                //if you update listOfStegoMethods, update also GetMethodCapacity()
                //for details read file MethodDescription.txt, keep it updated if changing following list!             
                //inform user about settings in [] brackets like exact delay if possible (constants)

                { 301, "IP Type of service / DiffServ (agresive) - " + GetMethodCapacity(301) + "b" },
                { 302, "IP Type of service / DiffServ - " + GetMethodCapacity(302) + "b" },
                { 303, String.Format("IP Identification [delay {0}s] - {1}b", (double)NetSenderClient.IpIdentificationChangeSpeedInMs/1000, GetMethodCapacity(303) )}, //adding exact time value to the name
                { 305, "IP flag (MF + offset (when applicable)) - " + GetMethodCapacity(305) + "b" },
                //TODO icmp methods are waiting for refactoring...
                { 331, String.Format("ICMP ping (standard) [delay {0}s] - {1}b", (double)NetSenderClient.delayIcmp/1000, GetMethodCapacity(331) )},
                { 333, "ICMP ping (identifier) - " + GetMethodCapacity(333) + "b" },    //TODO should be set on start of transaction and not changed in the time
                { 335, "ICMP ping (sequence number) - " + GetMethodCapacity(335) + "b" },   //TODO is actually changing all the time, improve by just incrementing
                //{ 451, "TCP (standard)- " + GetMethodCapacity(451) + "b" },
                //{ 453, "TCP ISN (once) - " + GetMethodCapacity(453) + "b" }, //use idea from 303
                //{ 455, "TCP Urgent pointer - " + GetMethodCapacity(455) + "b" }, //use idea from 305
                //{ 457, "TCP Options (timestamp) - " + GetMethodCapacity(457) + "b" },
                { 701, String.Format("DNS request (standard over UDP) [delay {0}s] - {1}b", (double)NetSenderClient.delayDns/1000, GetMethodCapacity(331)) },
                { 703, "DNS request (transaction id) - " + GetMethodCapacity(703) + "b" },
                { 705, "DNS request (response) - " + GetMethodCapacity(705) + "b" },                 
                //707 DNS flags https://tools.ietf.org/html/rfc1035#section-4.1.1, standard 0x00000100 //TODO update value Capacity

                { 731, "HTTP GET (over TCP) - 0b" }, //TODO
                //{ 733, "HTTP GET facebook picture - 64b" }, //TODO
                //HTTP Entity tag headers 
                        
                //TODO time channel! (ttl methods, resting value is magic value, round trip timer) (ping delay or TCP delay)
                //https://github.com/PcapDotNet/Pcap.Net/wiki/Pcap.Net-Tutorial-Gathering-Statistics-on-the-network-traffic
                //TODO TTL usage or similar (count TTL and use some value under as rest...)
            };

            return listOfStegoMethods; //DO NOT DYNAMICAL MODIFY THAT LIST DURING RUNNING
        }

        //service method
        public static int GetMethodCapacity(int id) //manually edited capacity of each method
        {
            Dictionary<int, int> capacity = new Dictionary<int, int>()
            {
                { 301, 8 },
                { 302, 2 },
                { 303, 16 },
                { 331, 0 },
                { 333, 16 },
                { 335, 16 },
                { 305, 13 },
                { 451, 0},
                { 453, 32 },
                { 455, 16 },
                { 457, 0 }, //TODO update when implemented               
                { 701, 0 },
                { 703, 16 },
                { 705, 32 },
                { 707, 0 },
                //{ ,},
                //{ ,},
                //{ ,},
                //{ ,},
                //{ ,},
                //{ ,},
                //{ ,},
            };

            if (capacity.ContainsKey(id))
            {
                return capacity[id];
            }
            else
            {
                return 0;
            }
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

        //service method for all
        private static string GetBinaryContentToSend(string secret, int usedbits) //returns value to steganogram for all methods
        {
            if (secret.Equals(""))
            {
                //exception handling                
                System.Diagnostics.StackTrace stackTrace = new System.Diagnostics.StackTrace(); // Get call stack                                
                throw new Exception("Internal error! Canot be sent empty message. Error caused by: " + stackTrace.GetFrame(1).GetMethod().Name);
            }

            string partOfSecret = "";
            try
            {
                partOfSecret = secret.Remove(usedbits, secret.Length - usedbits);
            }
            catch
            {
                partOfSecret = secret;
            }

            try
            {
                if (Double.Parse(partOfSecret) == 0 || partOfSecret[0].Equals("0")) //check if whole sequence is zero or it starts with zero
                {
                    return "0"; //send just zero and cut one bit from whole
                }
                else
                {
                    return partOfSecret; //return part of whole secret and value to be cutted from original like secret = secret.Remove(0, usedbits);
                }
            }
            catch //Unhandled Exception: System.FormatException: Input string was not in a correct format.
            {
                throw new Exception("Value " + partOfSecret + " caused an exception when converting to decimal number");
            }


        }

        //service method for all
        private static string GetBinaryStringFromReceived(string binvalue)
        {
            if (Double.Parse(binvalue) == 0)
            {
                return "0";
            }
            else
            {
                return binvalue;
            }
        }

        //---------------------------------------------------------------------------------------------------------------------

        //ip layer methods               
        public static Tuple<IpV4Layer, string> SetContent3Network(IpV4Layer ip, List<int> stegoUsedMethodIds, string secret, NetSenderClient sc = null, bool firstAndResetRunIP = false) //SENDER
        {
            if (ip == null || secret.Length == 0) { return null; } //extra protection

            foreach (int methodId in stegoUsedMethodIds) //process every method separately on this packet
            {
                switch (methodId)
                {
                    case 301: //IP (Type of service / DiffServ) agresive //SENDER
                        {
                            sc.AddInfoMessage("3IP: method " + methodId + " size of: " + GetMethodCapacity(methodId));
                            string content = GetBinaryContentToSend(secret, GetMethodCapacity(methodId));
                            ip.TypeOfService = Convert.ToByte(content, 2); //place content string
                            secret = secret.Remove(0, content.Length); //cut x bits from whole
                            if (content.Length == 0 || secret.Length == 0)
                            {
                                return new Tuple<IpV4Layer, string>(ip, secret); //nothing more          
                            }
                            break;
                        }
                    case 302: //IP (Type of service / DiffServ) //SENDER
                        {
                            sc.AddInfoMessage("3IP: method " + methodId + " size of: " + GetMethodCapacity(methodId));
                            string content = GetBinaryContentToSend(secret, GetMethodCapacity(methodId));
                            ip.TypeOfService = Convert.ToByte(content, 2); //place content string
                            secret = secret.Remove(0, content.Length); //cut x bits from whole
                            if (content.Length == 0 || secret.Length == 0)
                            {
                                return new Tuple<IpV4Layer, string>(ip, secret); //nothing more          
                            }
                            break;
                        }
                    case 303: //IP (Identification) //SENDER
                        {
                            if (firstAndResetRunIP == true)
                            {
                                sc.AddInfoMessage("3IP: method " + methodId + " size of: " + GetMethodCapacity(methodId) + " it's first or reseted run");
                                string content = GetBinaryContentToSend(secret, GetMethodCapacity(methodId));

                                ip.Identification = Convert.ToUInt16(content, 2); //place content string
                                secret = secret.Remove(0, content.Length); //cut x bits from whole
                                if (content.Length == 0 || secret.Length == 0)
                                {
                                    return new Tuple<IpV4Layer, string>(ip, secret); //nothing more          
                                }
                            }
                            break;
                        }
                    case 305: //IP flag (MF + offset) //SENDER
                        {
                            string content = GetBinaryContentToSend(secret, GetMethodCapacity(methodId));
                            ushort offset = Convert.ToUInt16(content, 2);
                            if (offset % 8 == 0 && offset != 0) //offset rule
                            {
                                sc.AddInfoMessage("3IP: method " + methodId + " size of: " + GetMethodCapacity(methodId)); //offset can be from 0 to 8191
                                ip.Fragmentation = new IpV4Fragmentation(IpV4FragmentationOptions.MoreFragments, offset); //also IpV4FragmentationOptions.DoNotFragment posssible
                                secret = secret.Remove(0, content.Length); //remove only when is used...
                            }
                            else
                            {
                                //sc.AddInfoMessage("Offset was: " + offset + ", so it wasnt used, modulo: " + offset % 8);
                                ip.Fragmentation = new IpV4Fragmentation(IpV4FragmentationOptions.None, 0); //end of fragmentation                                     
                            }

                            if (content.Length == 0 || secret.Length == 0)
                            {
                                return new Tuple<IpV4Layer, string>(ip, secret); //nothing more          
                            }
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
                    case 301: //IP (Type of service / DiffServ agresive) //RECEIVER
                        {
                            rs.AddInfoMessage("3IP: method " + methodId); //add number of received bits in this iteration
                            string binvalue = Convert.ToString(ip.TypeOfService, 2).PadLeft(GetMethodCapacity(methodId), '0');
                            BlocksOfSecret.Add(GetBinaryStringFromReceived(binvalue));
                            break;
                        }
                    case 302: //IP (Type of service / DiffServ) //RECEIVER
                        {
                            rs.AddInfoMessage("3IP: method " + methodId);
                            string binvalue = Convert.ToString(ip.TypeOfService, 2).PadLeft(GetMethodCapacity(methodId), '0');
                            BlocksOfSecret.Add(GetBinaryStringFromReceived(binvalue));
                            break;
                        }
                    case 303: //IP (Identification) //RECEIVER
                        {
                            rs.AddInfoMessage("3IP: method " + methodId); //add number of received bits in this iteration
                            string binvalue = Convert.ToString(ip.Identification, 2).PadLeft(GetMethodCapacity(methodId), '0');
                            if (IdentificationIP != binvalue) //do not add value when it didnt change
                            {
                                IdentificationIP = binvalue; //remember for next time
                                BlocksOfSecret.Add(GetBinaryStringFromReceived(binvalue));
                            }
                            break;
                        }
                    case 305: //IP flag (MF + offset) //RECEIVER
                        {
                            if (ip.Fragmentation.Options == IpV4FragmentationOptions.MoreFragments)
                            {
                                rs.AddInfoMessage("3IP: method " + methodId);
                                string binvalue = Convert.ToString(ip.Fragmentation.Offset, 2).PadLeft(GetMethodCapacity(methodId), '0');
                                BlocksOfSecret.Add(GetBinaryStringFromReceived(binvalue));
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
            if (icmp == null || secret.Length == 0) { return null; } //extra protection            

            //TODO implement new method handling
            foreach (int methodId in stegoUsedMethodIds) //process every method separately on this packet
            {
                switch (methodId)
                {
                    case IcmpGenericPing: //ICMP (standard, for other layers) //SENDER (alias 331, but value used in code)
                        {
                            sc.AddInfoMessage("3ICMP: method " + methodId);
                            icmp.SequenceNumber = SequenceNumberICMP++; //legacy sequence number
                            icmp.Identifier = (ushort)rand.Next(0, 65535);
                            //add delay 1000 miliseconds on parent object
                            break;
                        }
                    case 333: //ICMP (Identifier) //SENDER
                        {
                            sc.AddInfoMessage("3ICMP: method " + methodId);
                            if (!stegoUsedMethodIds.Contains(335)) //do not overwrite sequence number when that method selected
                            {
                                icmp.SequenceNumber = SequenceNumberICMP++; //legacy sequence number
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
                                    //icmp.Identifier = Convert.ToUInt16(secret.PadLeft(usedbits, '0'), 2); //using rest + padding
                                    icmp.Identifier = Convert.ToUInt16(secret, 2); //using rest + padding
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
                                    icmp.SequenceNumber = Convert.ToUInt16(secret, 2); //using rest + padding .PadLeft(usedbits, '0')
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

            //TODO implement new method handling
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
        public static Tuple<TcpLayer, string> SetContent4Tcp(TcpLayer tcp, List<int> stegoUsedMethodIds, string secret, NetSenderClient sc = null, bool firstAndResetRunTCP = false)
        {
            if (tcp == null || secret.Length == 0) { return null; } //extra protection

            foreach (int methodId in stegoUsedMethodIds)
            {
                //needs to handle states of TCP to read only from proper state like SYN, SYNACK

                switch (methodId)
                {
                    case 451: //TCP (standard, for other layers) //SENDER
                        {
                            sc.AddInfoMessage("4TCP: method " + methodId + " (no stehanography included)"); //clean version
                            tcp.SequenceNumber = NetStandard.GetSynOrAckRandNumber();
                            break;
                        }
                    case 453: //TCP sequence number (initialization only) //SENDER
                        {
                            if (firstAndResetRunTCP == true)
                            {
                                sc.AddInfoMessage("4TCP: method " + methodId + " size of: " + GetMethodCapacity(methodId) + " it's first or reseted run");
                                string content = GetBinaryContentToSend(secret, GetMethodCapacity(methodId));

                                tcp.SequenceNumber = Convert.ToUInt32(content, 2); //place content string
                                secret = secret.Remove(0, content.Length); //cut x bits from whole
                                if (content.Length == 0 || secret.Length == 0)
                                {
                                    return new Tuple<TcpLayer, string>(tcp, secret); //nothing more          
                                }
                            }
                            break;
                        }
                    case 455: //TCP Urgent pointer //SENDER
                        {
                            //TODO implement
                            //tcp.ControlBits = tcp.TcpControlBits.Urgent;
                            //tcp.UrgentPointer = 16 bit 
                            break;
                        }
                    case 457: //TCP
                        {
                            //TODO implement //display filter: tcp.options.time_stamp
                            //http://ithitman.blogspot.fi/2013/02/tcp-timestamp-demystified.html
                            //tcp.TcpOptions = new TcpOptionTimestamp(555, 555); //https://github.com/PcapDotNet/Pcap.Net/blob/master/PcapDotNet/src/PcapDotNet.Packets/Transport/TcpOptionTimestamp.cs
                            break;
                        }
                }
            }

            return new Tuple<TcpLayer, string>(tcp, secret);
        }

        public static string GetContent4Network(TcpDatagram tcp, List<int> stegoUsedMethodIds, NetReceiverServer rs = null) //RECEIVER
        {
            if (tcp == null) { return null; } //extra protection
            List<string> BlocksOfSecret = new List<string>();

            foreach (int methodId in stegoUsedMethodIds) //process every method separately on this packet
            {
                switch (methodId)
                {
                    case 451: //TCP standard //RECEIVER
                        {
                            rs.AddInfoMessage("4TCP: method " + methodId + " (no stehanography included)");
                            break;
                        }
                    case 453: //TCP sequence number (initialization only) //RECEIVER
                        {
                            rs.AddInfoMessage("4TCP: method " + methodId);
                            string binvalue = Convert.ToString(tcp.SequenceNumber, 2).PadLeft(GetMethodCapacity(methodId), '0');
                            if (IdentificationTCP != binvalue) //do not add value when it didnt change, principe from 303
                            {
                                IdentificationTCP = binvalue; //remember for next time
                                BlocksOfSecret.Add(GetBinaryStringFromReceived(binvalue));
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

        //-L5-to-L7------------------------------------------------------------------------------------------------------------

        //L7-dns
        public static Tuple<DnsLayer, string> SetContent7Dns(DnsLayer dns, List<int> stegoUsedMethodIds, string secret, NetSenderClient sc = null) //SENDER
        {
            if (dns == null || secret.Length == 0) { return null; } //extra protection

            foreach (int methodId in stegoUsedMethodIds) //process every method separately on this packet
            {
                switch (methodId)
                {
                    case 701: //DNS regular //SENDER
                        {
                            sc.AddInfoMessage("7DNS: legacy method " + methodId + " (no data removed)");
                            dns.Id = (ushort)rand.Next(0, 65535);
                            break;
                        }
                    case 703: //DNS (transaction id) //SENDER
                        {
                            sc.AddInfoMessage("7DNS: method " + methodId + " size of: " + GetMethodCapacity(methodId));
                            string content = GetBinaryContentToSend(secret, GetMethodCapacity(methodId));

                            dns.Id = Convert.ToUInt16(content, 2); //place content string 
                            //DEBUG: dns was in try-catch setting content = 0 when error, probably old debug...
                            secret = secret.Remove(0, content.Length); //cut x bits from whole
                            if (content.Length == 0 || secret.Length == 0)
                            {
                                return new Tuple<DnsLayer, string>(dns, secret); //nothing more               
                            }
                            break;
                        }
                    case 705: //DNS request containing anwer with stego //SENDER
                        {
                            sc.AddInfoMessage("7DNS: method " + methodId + " size of: " + GetMethodCapacity(methodId));
                            string content = GetBinaryContentToSend(secret, GetMethodCapacity(methodId));

                            //make from content IP address form
                            string stegoInFormOfIpAddress = "255.255.255.255";
                            if (content.Equals("0"))
                            {
                                stegoInFormOfIpAddress = "0.0.0.0"; //TODO less suspicious
                            }
                            else //parse content to IP
                            {
                                try
                                {
                                    if (content.Length % 4 != 0)
                                    {
                                        content = content.PadLeft(32, '0');
                                    }

                                    List<string> octets = new List<string>();
                                    for (int i = 0; i < content.Length; i = i + 8)
                                    {
                                        if (content.Length - i >= 8)
                                            octets.Add(content.Substring(i, 8));
                                        else
                                            octets.Add(content.Substring(i, ((content.Length - i))));
                                    }

                                    stegoInFormOfIpAddress = Convert.ToUInt16(octets[0], 2) + "." + Convert.ToUInt16(octets[1], 2) + "." + Convert.ToUInt16(octets[2], 2) + "." + Convert.ToUInt16(octets[3], 2);
                                    sc.AddInfoMessage("7DNS: IP is + " + stegoInFormOfIpAddress + " made from: " + content);
                                }
                                catch
                                {
                                    sc.AddInfoMessage("7DNS: carrying info in fake IP failed for this datagram.");
                                }
                            }
                            IpV4Address fakeIp = new IpV4Address(stegoInFormOfIpAddress);

                            //System.OverflowException: 
                            List<DnsQueryResourceRecord> dnsRequest = new List<DnsQueryResourceRecord>() { ((DnsQueryResourceRecord)dns.Queries.First()) };
                            DnsQueryResourceRecord dnsRequestOrig = dnsRequest.First();
                            DnsDataResourceRecord dnsAnswerFake = new DnsDataResourceRecord(dnsRequestOrig.DomainName, dnsRequestOrig.DnsType, DnsClass.Internet, 128, new DnsResourceDataIpV4(fakeIp));

                            //new DNS layer                            
                            dns.IsQuery = true;
                            dns.Queries = new List<DnsQueryResourceRecord>() { dnsRequestOrig }; //keep request
                            dns.IsResponse = true;
                            dns.Answers = new List<DnsDataResourceRecord>() { dnsAnswerFake };

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

            foreach (int methodId in stegoUsedMethodIds) //process every method separately in this packet
            {
                switch (methodId)
                {
                    case 701: //DNS (pure) //RECEIVER
                        {
                            rs.AddInfoMessage("7DNS: method " + methodId + " (no stehanography included)");
                            break;
                        }
                    case 703: //DNS (transaction ID) //RECEIVER
                        {
                            rs.AddInfoMessage("7DNS: method " + methodId);
                            string binvalue = Convert.ToString(dns.Id, 2).PadLeft(GetMethodCapacity(methodId), '0');
                            BlocksOfSecret.Add(GetBinaryStringFromReceived(binvalue));
                            break;
                        }
                    case 705:
                        {
                            //throw NotImplementedException;
                            //alisfliksajfkaf++;
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


        //L7-http
        internal static Tuple<HttpLayer, string> SetContent7Http(HttpLayer http, List<int> stegoUsedMethodIds, string secret, NetSenderClient sc)
        {
            if (http == null) { return null; } //extra protection

            foreach (int methodId in stegoUsedMethodIds) //process every method separately on this packet
            {
                switch (methodId)
                {
                    case 731: //HTTP clean //SENDER
                        {
                            sc.AddInfoMessage("7HTTP: legacy method " + methodId + " (no data removed)");
                            break;
                        }
                    case 733: //HTTP GET facebook picture //SENDER
                        {
                            sc.AddInfoMessage("7HTTP: method " + methodId);
                            const int usedbits = 200;
                            try
                            {
                                string partOfSecret = secret.Remove(usedbits, secret.Length - usedbits);

                                //request for FB image                                                                
                                //https://scontent-arn2-1.xx.fbcdn.net/v/t1.0-9/28783581_2044295905785459_4786842833526980608_o.jpg?_nc_cat=0&oh=f393eabff543c0014fa7d549a606cd72&oe=5B3439EE
                                //https://scontent-arn2-1.xx.fbcdn.net/v/t31.0-8/26756412_2019306211617762_7982736838983831551_o.jpg?_nc_cat=0&oh=1fe51c45d8053ae7b0f95570763e3cfd&oe=5B729DA3
                                //https://www.facebook.com/<username>/photos/a.1693236240891429.1073741827.1693231710891882/2042454925969557/?type=3&theater

                                //instagram                                
                                //https://scontent-arn2-1.cdninstagram.com/vp/8c1b8efbaac6831e2a15d59e6a047276/5B6D8993/t51.2885-15/e35/29417270_195771601230887_3084806938333020160_n.jpg
                                //https://scontent-arn2-1.cdninstagram.com/vp/d9d046183c558e2065c5c6b77ded7cd8/5B74D9C8/t51.2885-15/e35/29417740_596673960668154_5630438044696838144_n.jpg

                                //twitter
                                //https://pbs.twimg.com/media/DUj28AMXkAEy8q7.jpg:large
                                //https://pbs.twimg.com/media/DZ-5xFDU0AAJRPu.jpg:large

                                //pinterest


                                secret = secret.Remove(0, usedbits);
                            }
                            catch
                            {
                                if (secret.Length != 0)
                                {
                                    //dns.Id = Convert.ToUInt16(secret.PadLeft(usedbits, '0'), 2); //using rest + padding
                                    secret = secret.Remove(0, secret.Length);
                                }
                                return new Tuple<HttpLayer, string>(http, secret); //nothing more                                         
                            }
                            break;
                        }
                }
            }
            return new Tuple<HttpLayer, string>(http, secret);
        }

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
                            rs.AddInfoMessage("7HTTP: method " + methodId);

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

