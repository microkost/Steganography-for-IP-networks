using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SteganoNetLib
{
    public class NetSteganography //not static
    {
        private readonly Dictionary<int, string> listOfStegoMethods;

        public NetSteganography(List<int> listOfMethodIndexes)
        {
             listOfStegoMethods = NetSteganography.GetListOfStegoMethods();
        }

        public static Dictionary<int, string> GetListOfStegoMethods()
        {
            //TODO https://stackoverflow.com/questions/27631137/tuple-vs-dictionary-differences //<Tuple<Packet, String>
            Dictionary<int, string> listOfStegoMethods = new Dictionary<int, string>();

            //previously public static List<String> listOfStegoMethods = new List<String>() { "ICMP using identifier and sequence number", "TCP using sequence number and urgent field", "IP", "ISN + IP ID", "DNS using ID" }; //List of methods used in code and GUI, index of method is important!

            listOfStegoMethods.Add(0, "IP (Type of service)");
            listOfStegoMethods.Add(1, "IP (Identification)");
            listOfStegoMethods.Add(2, "IP (Flags)");

            return listOfStegoMethods; //DO NOT MODIFY THAT LIST DURING RUNNING
        }
    }


}
