using SteganoNetLib;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;

namespace SteganoNet.UI.Console
{
    public delegate void ThreadStart();
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

            System.Console.WriteLine("Welcome in Steganography for IP networks tool.");
            string role = "s"; //server or client

            if(SteganoNet.Lib.SystemCheck.AreSystemPrerequisitiesDone() == false) //just to be obvious
            {
                System.Console.WriteLine("Nessesary library WinPcap is not installed or PcapDotNet is not present.");
                System.Console.WriteLine("Press any key to exit... ");
                System.Console.ReadKey();
                return;
            }

            if (args.Length == 0 || args == null) //no user parametrized input = run configuration WIZARD
            {
                System.Console.WriteLine("Do you want to run configuration wizard? (y/n) n");
                //TODO WIZARD y/n etc... string ipSource = ConsoleTools.SelectInterface();

                System.Console.Write("\tIs this device (s)erver or (c)lient? (s/c) ");
                role = System.Console.ReadLine();
                System.Console.WriteLine("");                    
                //...
            }
            else //skip the wizard
            {
                role = "s"; //DEBUG TMP
                foreach (string arg in args) 
                {
                    System.Console.WriteLine("Received settings: ");
                    System.Console.Write("arg: %s ", arg);
                    //TODO PARSING parametres
                }
            }
           
            //config general
            string secretMessage = ""; //"VŠB - Technical University of Ostrava has long tradition in high quality engineering. Provides tertiary education in technical and economic sciences across a wide range of study programmes andcourses at the Bachelor’s, Master’s and Doctoral level. Our study programmes stand on a tradition going back more than 165 years, but reflect current, state of the art technologies and the needs of industry and society.";
            //string encryptedMessage = DataOperationsCrypto.DoCrypto(secretMessage); //mock
            Dictionary<int, string> stegoMethods = NetSteganography.GetListOfStegoMethods();

            //config local
            string ipSource = ConsoleTools.SelectInterface();
            //ushort port = 11000;

            //config remote
            string ipremote = "192.168.1.150";
            ushort portremote = 11001;
            
            if (String.Equals("s", role)) //its server
            {
                NetReceiverServer rs = new NetReceiverServer(ipSource);
                //rs.Secret = secretMessage; //client!
                rs.StegoMethod = stegoMethods[31]; //needs to know because of reply
                rs.IpDestinationInput = ipremote;
                rs.PortDestination = portremote;

                Thread receiverServerThread = new Thread(rs.Listening);
                receiverServerThread.Name = "ListeningAndReceivingThread";
                receiverServerThread.Start();
                //receiverServerThread.IsBackground = true;
                

                //Thread thread = new Thread(delegate () { ConsoleTools.writeInfo(rs); });                
                Thread writer = new Thread(new ParameterizedThreadStart(ConsoleTools.writeInfo));
                writer.Start(rs);
                writer.IsBackground = true;

                //solve receiving debug info from thread - events?
                //google how to keep focus on first thread and just print new info...

                //stop listening
                //run rs.GetSecretMessage(null)
                //stop thread
                //offer new run


                //solve how to run multiple instances of console in one time

                bool terminate = false;
                do
                {
                    System.Console.WriteLine("Is message received? (y/n) ");
                    string stopListening = System.Console.ReadLine();
                    if (String.Equals(stopListening, "y"))
                    {
                        string receivedString = rs.GetSecretMessage();
                        secretMessage = DataOperationsCrypto.ReadCrypto(receivedString);
                        terminate = true;
                        receiverServerThread.Abort();
                    }
                }
                while (terminate);



                //Do you want to 


                writer.Join();

            }
            else if (String.Equals("c", role)) //its client
            {
                NetSenderClient sc = new NetSenderClient();

            }
            else
            {
                System.Console.WriteLine("Sorry, I didnt understand your commands. Start again...");
            }
            
            System.Console.WriteLine("\nThat's all! Thank you for using Steganography for IP networks tool.");
            System.Console.ReadKey();            
        }
    }

}
