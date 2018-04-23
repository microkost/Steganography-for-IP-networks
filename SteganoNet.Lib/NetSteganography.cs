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
        public const int HttpDataInUrl = 733;


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
                //for details of methods read file MethodDescription.txt, keep it updated if changing smth here...
                //inform user about invisible settings in [] brackets like exact delay (if possible (constants))

                { 301, "IP Type of service / DiffServ (agresive) - " + GetMethodCapacity(301) + "b" },
                //{ 302, "IP Type of service / DiffServ - " + GetMethodCapacity(302) + "b" }, //OK, just messing testing with another option
                { 303, String.Format("IP Identification [delay {0}s] - {1}b", (double)NetSenderClient.IpIdentificationChangeSpeedInMs/1000, GetMethodCapacity(303) )}, //adding exact time value to the name
                { 305, "IP flag (MF + offset (when applicable)) - " + GetMethodCapacity(305) + "b" },
                { 331, String.Format("ICMP ping (NO STEGO) [delay {0}s] - {1}b", (double)NetSenderClient.delayIcmp/1000, GetMethodCapacity(331) )}, //TODO icmp methods are waiting for refactoring...
                { 333, "ICMP ping (identifier) - " + GetMethodCapacity(333) + "b" },    //TODO should be set on start of transaction and not changed in the time
                { 335, "ICMP ping (sequence number) - " + GetMethodCapacity(335) + "b" },   //TODO is actually changing all the time, improve by just incrementing
                //{ 451, "TCP (NO STEGO)- " + GetMethodCapacity(451) + "b" },
                //{ 453, "TCP ISN (once) - " + GetMethodCapacity(453) + "b" }, //use idea from 303
                //{ 455, "TCP Urgent pointer - " + GetMethodCapacity(455) + "b" }, //use idea from 305
                //{ 457, "TCP Options (timestamp) - " + GetMethodCapacity(457) + "b" },
                { 701, String.Format("DNS request (NO STEGO) [delay {0}s] - {1}b", (double)NetSenderClient.delayDns/1000, GetMethodCapacity(331)) },
                { 703, "DNS request (transaction id) - " + GetMethodCapacity(703) + "b" },
                { 705, "DNS request (response) - " + GetMethodCapacity(705) + "b" },                 
                //707 DNS flags https://tools.ietf.org/html/rfc1035#section-4.1.1, standard 0x00000100 //TODO update value Capacity
                { 731, "HTTP GET (NO STEGO) - " + GetMethodCapacity(731) + "b" },
                { 733, "HTTP GET (social media) - " + GetMethodCapacity(733) + "b" },  
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
                { 305, 13 },
                { 331, 0 },
                { 333, 16 },
                { 335, 16 },
                { 451, 0},
                { 453, 32 },
                { 455, 16 },
                { 457, 0 }, //TODO update when implemented
                { 701, 0 },
                { 703, 16 },
                { 705, 32 },
                { 707, 0 },
                { 731, 0 },
                { 733, 64 }, //could be any lenght, but needs to be %4 == 0 and %8 == 0
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

            if (secret[0].Equals('0')) //zero on start makes troubles
            {
                return "0";
            }

            string partOfSecret = "";
            try
            {
                partOfSecret = secret.Remove(usedbits, secret.Length - usedbits);
            }
            catch
            {
                partOfSecret = secret; //last phrase
            }

            try
            {
                System.Text.RegularExpressions.Regex r = new System.Text.RegularExpressions.Regex("^[0\\s]*$"); //checking even very long string for only zeros
                if (r.IsMatch(partOfSecret)) //check if whole sequence is zero or it starts with zero
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
            //if (Double.Parse(binvalue) == 0)
            System.Text.RegularExpressions.Regex r = new System.Text.RegularExpressions.Regex("^[0\\s]*$"); //checking even very long string for only zeros
            if (r.IsMatch(binvalue) || binvalue[0].Equals("0")) //check if whole sequence is zero or it starts with zero
            {
                return "0" + NetReceiverServer.ZeroSeparator;
            }
            else
            {
                return binvalue + NetReceiverServer.WordSeparator;
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
                                sc.AddInfoMessage("3IP: method " + methodId + " size of: " + GetMethodCapacity(methodId)); //offset can be from 0 to 8191 based on standard
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
                            rs.AddInfoMessage("3IP: method " + methodId + " size of: " + GetMethodCapacity(methodId)); //add number of received bits in this iteration
                            string binvalue = Convert.ToString(ip.TypeOfService, 2).PadLeft(GetMethodCapacity(methodId), '0');
                            BlocksOfSecret.Add(GetBinaryStringFromReceived(binvalue));
                            break;
                        }
                    case 302: //IP (Type of service / DiffServ) //RECEIVER
                        {
                            rs.AddInfoMessage("3IP: method " + methodId + " size of: " + GetMethodCapacity(methodId));
                            string binvalue = Convert.ToString(ip.TypeOfService, 2).PadLeft(GetMethodCapacity(methodId), '0');
                            BlocksOfSecret.Add(GetBinaryStringFromReceived(binvalue));
                            break;
                        }
                    case 303: //IP (Identification) //RECEIVER
                        {
                            string binvalue = Convert.ToString(ip.Identification, 2).PadLeft(GetMethodCapacity(methodId), '0');
                            if (IdentificationIP != binvalue) //do not add value when it didnt change
                            {
                                rs.AddInfoMessage("3IP: method " + methodId + " size of: " + GetMethodCapacity(methodId)); //add number of received bits in this iteration
                                IdentificationIP = binvalue; //remember for next time
                                BlocksOfSecret.Add(GetBinaryStringFromReceived(binvalue));
                            }
                            break;
                        }
                    case 305: //IP flag (MF + offset) //RECEIVER
                        {
                            if (ip.Fragmentation.Options == IpV4FragmentationOptions.MoreFragments)
                            {
                                rs.AddInfoMessage("3IP: method " + methodId + " size of: " + GetMethodCapacity(methodId));
                                string binvalue = Convert.ToString(ip.Fragmentation.Offset, 2).PadLeft(GetMethodCapacity(methodId), '0');
                                BlocksOfSecret.Add(GetBinaryStringFromReceived(binvalue));
                            }
                            break;
                        }
                }
            }

            if (BlocksOfSecret.Count != 0) //providing value output
            {
                return string.Join(NetReceiverServer.WordSeparator, BlocksOfSecret.ToArray()); //joining binary substring
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
                            sc.AddInfoMessage("3ICMP: method " + methodId + " size of: " + GetMethodCapacity(methodId));
                            icmp.SequenceNumber = SequenceNumberICMP++; //needs to be generated, otherwise 0
                            icmp.Identifier = (ushort)rand.Next(0, 65535);
                            //add delay 1000 miliseconds on parent object
                            break;
                        }
                    case 333: //ICMP (Identifier) //SENDER
                        {
                            sc.AddInfoMessage("3ICMP: method " + methodId + " size of: " + GetMethodCapacity(methodId));

                            if (!stegoUsedMethodIds.Contains(335)) //do not overwrite sequence number when that method selected, thats stupid, do not touch then
                            {
                                icmp.SequenceNumber = SequenceNumberICMP++; //legacy sequence number 
                            }

                            string content = GetBinaryContentToSend(secret, GetMethodCapacity(methodId));
                            icmp.Identifier = Convert.ToUInt16(content, 2);
                            secret = secret.Remove(0, content.Length); //cut x bits from whole
                            if (content.Length == 0 || secret.Length == 0)
                            {
                                return new Tuple<IcmpEchoLayer, string>(icmp, secret); //nothing more      
                            }
                            break;
                        }
                    case 335: //ICMP (Sequence number) //SENDER
                        {
                            sc.AddInfoMessage("3ICMP: method " + methodId + " size of: " + GetMethodCapacity(methodId));

                            if (!stegoUsedMethodIds.Contains(333)) //do not overwrite identifier when that method selected
                            {
                                icmp.Identifier = icmp.Identifier = (ushort)rand.Next(0, 65535); //legacy Identifier number
                            }

                            string content = GetBinaryContentToSend(secret, GetMethodCapacity(methodId));
                            icmp.SequenceNumber = Convert.ToUInt16(content, 2);
                            secret = secret.Remove(0, content.Length); //cut x bits from whole
                            if (content.Length == 0 || secret.Length == 0)
                            {
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
                            rs.AddInfoMessage("3IP: method " + methodId + " size of: " + GetMethodCapacity(methodId)); //add number of received bits in this iteration
                            string binvalue = Convert.ToString(icmp.Identifier, 2).PadLeft(GetMethodCapacity(methodId), '0');
                            BlocksOfSecret.Add(GetBinaryStringFromReceived(binvalue));
                            break;
                        }
                    case 335: //ICMP (Sequence number) RECEIVER
                        {
                            rs.AddInfoMessage("3IP: method " + methodId + " size of: " + GetMethodCapacity(methodId)); //add number of received bits in this iteration
                            string binvalue = Convert.ToString(icmp.SequenceNumber, 2).PadLeft(GetMethodCapacity(methodId), '0');
                            BlocksOfSecret.Add(GetBinaryStringFromReceived(binvalue));
                            break;                            
                        }
                }
            }

            if (BlocksOfSecret.Count != 0) //providing value output
            {
                return string.Join(NetReceiverServer.WordSeparator, BlocksOfSecret.ToArray()); //joining binary substring
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
                return string.Join(NetReceiverServer.WordSeparator, BlocksOfSecret.ToArray()); //joining binary substring
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
                            sc.AddInfoMessage("7DNS: legacy method " + methodId + " (no data)");
                            //dns.Id = (ushort)rand.Next(0, 65535);
                            break;
                        }
                    case 703: //DNS (transaction id) //SENDER
                        {
                            sc.AddInfoMessage("7DNS: method " + methodId + " size of: " + GetMethodCapacity(methodId));
                            string content = GetBinaryContentToSend(secret, GetMethodCapacity(methodId));
                            dns.Id = Convert.ToUInt16(content, 2); //place content string 
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
                            int sizeToCut = content.Length;

                            //make from content IP address form
                            string stegoInFormOfIpAddress = "255.255.255.255";
                            if (content.Equals("0")) //its already checked and converted into "0" by GetBinaryContentToSend()
                            {
                                stegoInFormOfIpAddress = "0.0.0.0"; //TODO less suspicious
                                sc.AddInfoMessage("7DNS: IP is + " + stegoInFormOfIpAddress);
                                sizeToCut = 1;
                            }
                            else //parse content to IP address
                            {
                                try
                                {
                                    if (content.Length % 8 != 0 || content.Length < 32)
                                    {
                                        //sc.AddInfoMessage("7DNS: " + methodId + ", content was padded, originally: " + content.Length);
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
                                    sc.AddInfoMessage("7DNS: IP is + " + stegoInFormOfIpAddress);
                                }
                                catch
                                {
                                    sc.AddInfoMessage("7DNS: carrying info in fake IP FAILED for this datagram."); //TODO what is  in IP then?
                                    sizeToCut = 0; //do not cut                                    
                                }
                            }
                            IpV4Address fakeIp = new IpV4Address(stegoInFormOfIpAddress);

                            List<DnsQueryResourceRecord> dnsRequest = new List<DnsQueryResourceRecord>() { ((DnsQueryResourceRecord)dns.Queries.First()) };
                            DnsQueryResourceRecord dnsRequestOrig = dnsRequest.First();

                            //new DNS layer                            
                            DnsDataResourceRecord dnsAnswerFake = new DnsDataResourceRecord(dnsRequestOrig.DomainName, dnsRequestOrig.DnsType, DnsClass.Internet, 128, new DnsResourceDataIpV4(fakeIp));
                            dns.IsQuery = true;
                            //dns.IsResponse = true; //its mutual exclusive, one or the other
                            dns.Queries = new List<DnsQueryResourceRecord>() { dnsRequestOrig }; //keep request                            
                            dns.Answers = new List<DnsDataResourceRecord>() { dnsAnswerFake };

                            secret = secret.Remove(0, sizeToCut); //cut x bits from whole
                            if (content.Length == 0 || secret.Length == 0)
                            {
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
                            if (dns.Answers.Count > 0 && dns.Queries.Count > 0) //if it is in DNS request...
                            {
                                DnsDataResourceRecord request = dns.Answers.First(); //take just one request from collection                               
                                IpV4Address fakeIpV4 = ((DnsResourceDataIpV4)request.Data).Data; //wtf parsing

                                string binvalue = "";
                                if (fakeIpV4.Equals(new IpV4Address("0.0.0.0"))) //could also come 255.255.255.255, what if it is data?
                                {
                                    BlocksOfSecret.Add(GetBinaryStringFromReceived("0"));
                                }
                                else
                                {
                                    string[] parts = (fakeIpV4.ToString()).Split('.'); //start to parse
                                    foreach (string octet in parts)
                                    {
                                        binvalue += (Convert.ToString(Int32.Parse(octet), 2).PadLeft(8, '0'));
                                    }
                                    BlocksOfSecret.Add(GetBinaryStringFromReceived(binvalue));
                                }
                                rs.AddInfoMessage("7DNS: method " + methodId + "\tIP: " + fakeIpV4);                                
                            }
                            break;
                        }
                }
            }

            if (BlocksOfSecret.Count != 0) //providing value output
            {
                return string.Join(NetReceiverServer.WordSeparator, BlocksOfSecret.ToArray()); //joining binary substring
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
                    case 733: //HTTP GET social network picture //SENDER
                        {
                            sc.AddInfoMessage("7HTTP: method " + methodId + " size of: " + GetMethodCapacity(methodId));

                            List<string> services = NetDevice.GetSocialMediaDomains();
                            List<string> appendix = NetDevice.GetSocialMediaSuffix();
                            string oneService = services[rand.Next(services.Count)];
                            string oneApendix = appendix[rand.Next(appendix.Count)];

                            //cut content to some smaller parts and convert them to hex
                            string content = GetBinaryContentToSend(secret, GetMethodCapacity(methodId));
                            int sizeToCut = content.Length;
                            string urlpart = "";

                            string hexValue = String.Format("{0:X4}", Convert.ToUInt64(content, 2));
                            if (hexValue == "0000")
                            {
                                hexValue = "0"; //should be smth else
                            }
                            urlpart = hexValue.ToString().ToLower();

                            if (urlpart.Equals("0"))
                            {
                                urlpart = "8_bZH7ZEKz8SLRG1fo7evhDeaTdzIAPsQCJoC"; //static string replaced by 0, TODO dynamical like NetDevice.Get...()
                            }

                            string url = oneService + urlpart + oneApendix; //place content string in HEX
                            secret = secret.Remove(0, sizeToCut); //cut x bits from whole
                            sc.AddInfoMessage("7HTTP: Asking: " + url);

                            //make request
                            HttpRequestLayer httpFakeRequest = (HttpRequestLayer)http;
                            httpFakeRequest.Uri = url;
                            http = (HttpLayer)httpFakeRequest;

                            if (content.Length == 0 || secret.Length == 0)
                            {
                                return new Tuple<HttpLayer, string>(httpFakeRequest, secret); //nothing more               
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
                    case 733: //HTTP GET social network picture //RECEIVER
                        {
                            if (http.IsRequest)
                            {
                                HttpRequestDatagram httpReq = (HttpRequestDatagram)http;
                                string url = httpReq.Uri;
                                rs.AddInfoMessage("7HTTP: method " + methodId + " received: " + url);

                                //work for regex to cut the message from url, now workaround
                                List<string> services = NetDevice.GetSocialMediaDomains();
                                List<string> appendix = NetDevice.GetSocialMediaSuffix();
                                foreach (string prependix in services)
                                {
                                    if (url.Contains(prependix)) //remove everything before actuall message
                                    {
                                        url = url.Replace(prependix, "");
                                    }
                                }
                                foreach (string append in appendix) //remove everything after actuall message
                                {
                                    if (url.Contains(append))
                                    {
                                        url = url.Replace(append, "");
                                    }
                                }
                                if (url.Equals("8_bZH7ZEKz8SLRG1fo7evhDeaTdzIAPsQCJoC")) //static string replaced by 0, TODO dynamical like NetDevice.Get...()
                                {
                                    url = "0";
                                }
                                //rs.AddInfoMessage("7HTTP: method " + methodId + " received: " + url);

                                //convert message from URL to binary
                                string binarystring = Convert.ToString(Convert.ToInt64(url, 16), 2).PadLeft(url.Length * 4, '0');
                                string binvalue = GetBinaryStringFromReceived(binarystring); //check string
                                if (binvalue.Equals("0000") || binvalue.Equals("0"))
                                {
                                    //binvalue = "0"; //recognize zero strings
                                    BlocksOfSecret.Add(GetBinaryStringFromReceived("0"));
                                }
                                else
                                {
                                    int normalLenghtOfReceivedHexaMessage = (GetMethodCapacity(methodId) / 4);  //WARNING, calculation...
                                    /*
                                    if (url.Length < normalLenghtOfReceivedHexaMessage)
                                    {
                                        //do not pad this message to full lenght since its shorter (last one)
                                        while (binvalue[0].Equals('0') && binvalue.Length > 1) //cut intro zeros from string - padding effect, no zeros at the start
                                        {
                                            binvalue = binvalue.Remove(0, 1); //cut first zero
                                        }
                                    }
                                    else
                                    {
                                        binvalue = binvalue.PadLeft(GetMethodCapacity(methodId), '0'); //pad message to normal lenght
                                    }
                                    */
                                    binvalue = binvalue.PadLeft(GetMethodCapacity(methodId), '0'); //pad message to normal lenght
                                    BlocksOfSecret.Add(GetBinaryStringFromReceived(binvalue));
                                }                                
                            }
                            break;
                        }
                }
            }

            if (BlocksOfSecret.Count != 0) //providing value output
            {
                return string.Join(NetReceiverServer.WordSeparator, BlocksOfSecret.ToArray()); //joining binary substring
            }
            else
            {
                return null;
            }
        }
    }
}

