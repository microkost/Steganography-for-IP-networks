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

            //general
            string secretMessage = "VŠB - Technical University of Ostrava has long tradition in high quality engineering. Provides tertiary education in technical and economic sciences across a wide range of study programmes andcourses at the Bachelor’s, Master’s and Doctoral level. Our study programmes stand on a tradition going back more than 165 years, but reflect current, state of the art technologies and the needs of industry and society. Education is organized within 7 Faculties and 3 All-University Study Programmes.";
            string encryptedMessage = DataOperationsCrypto.DoCrypto(secretMessage); //mock
            Dictionary<int, string> stegoMethods = NetDevice.GetListOfStegoMethods();

            //local
            List<String> ipv4localadd = NetDevice.GetIPv4addressesLocal();            
            //ushort port = 11000;

            //remote
            string ipremote = "192.168.1.150";
            ushort portremote = 11001;            

            if (args[0] == "s") //its server
            {
                NetReceiverServer rs = new NetReceiverServer(ipv4localadd.First());
                rs.Secret = secretMessage;
                rs.StegoMethod = stegoMethods[0]; //needs to know because of reply
                rs.IpDestinationInput = ipremote;
                rs.PortDestination = portremote;

                //new thread
            }
            else //its client
            {             
                NetSenderClient sc = new NetSenderClient();

            }

            

        }
    }
}
