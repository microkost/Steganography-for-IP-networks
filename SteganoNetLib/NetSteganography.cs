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
             listOfStegoMethods = NetDevice.GetListOfStegoMethods();
        }
    }
}
