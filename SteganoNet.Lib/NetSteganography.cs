using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PcapDotNet.Packets.IpV4;

namespace SteganoNetLib
{
    public class NetSteganography //not static
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
             * Logic of ID integers:
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
            listOfStegoMethods.Add(320, "ICMP ()");


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

        public static string getContent3Network(IpV4Datagram ip, List<int> stegoUsedMethodIds)
        {
            //public vs internal            
            //throw new NotImplementedException();
            return "hello NotImplementedException";
        }
    }


}
