using SteganoNetLib;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SteganoNet.UI.Console
{
    class Program
    {       
        static void Main(string[] args)
        {

            //select role
            //select interface
            //select running port
            //choose steganographic method
            //run
            //stop
            //analyze results

            if (args.Length == 0 || args == null)
            {
                System.Console.WriteLine("Please enter a argument.");
                return;
            }

            foreach (string arg in args)
            {
                System.Console.WriteLine("Received settings: ");
                System.Console.Write("arg: %s ", arg);
            }

            List<String> ipv4localadd = NetDevice.GetIPv4addressesLocal();
            Dictionary<int, string> stegoMethods = NetDevice.GetListOfStegoMethods();

            if (args[0] == "s") //its server
            {
                NetReceiverServer rs = new NetReceiverServer(ipv4localadd.First(), 11000);
                rs.StegoMethod = stegoMethods[0];
                
            }
            else //its client
            {             
                NetSenderClient sc = new NetSenderClient();

            }

            

        }
    }
}
