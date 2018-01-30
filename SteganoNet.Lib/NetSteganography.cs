using System.Collections.Generic;
using System.Linq;
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
            listOfStegoMethods.Add(341, "ICMP ()");

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
            if(source == null)
            {
                source = GetListOfStegoMethods().Keys.ToList(); //TODO test
            }

            IEnumerable<int> listOfIpMethods = from num in source where num >= startValue && num <= endValue select num;
            return listOfIpMethods.ToList();
        }

        //ip layer methods
        public static string getContent3Network(IpV4Datagram ip, List<int> stegoUsedMethodIds, NetReceiverServer rsForInfoMessages = null)
        {
            //public vs internal?
            List<string> LocalMethodMessages = new List<string>();
            //if(ip == null){retrun null}

            foreach(int methodId in stegoUsedMethodIds) //process every method separately on this packet
            {
                LocalMethodMessages.Add("3IP: method " + methodId);
                switch (methodId)
                {
                    case 301:
                        //td
                        break;
                    case 302:
                        //td
                        break;                    
                }
            }          

            if(rsForInfoMessages != null)
            { 
                foreach(string localMessageToGlobal in LocalMethodMessages)
                {
                    rsForInfoMessages.AddInfoMessage(localMessageToGlobal);
                }
                
            }

            return "hello NotImplementedException";
        }

        //tcp layer methods

        //udp layer methods - skipped by assigment

        //application layer methods
    }


}
