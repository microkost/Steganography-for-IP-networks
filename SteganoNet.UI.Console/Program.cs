using SteganoNetLib;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;

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

            System.Console.WriteLine("Welcome in Steganography for IP networks tool.\n");
            string role = "s"; //server or client

            if (SteganoNet.Lib.SystemCheck.AreSystemPrerequisitiesDone() == false) //just to be obvious
            {
                System.Console.WriteLine("Nessesary library WinPcap is not installed or PcapDotNet is not present.");
                System.Console.WriteLine("Press any key to exit... ");
                System.Console.ReadKey();
                return;
            }

            if (args.Length == 0 || args == null) //no user parametrized input = run configuration WIZARD
            {
                System.Console.WriteLine("Do you want to run configuration wizard? (y/n) y");
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
            string messageReadable = ""; //"VŠB - Technical University of Ostrava has long tradition in high quality engineering. Provides tertiary education in technical and economic sciences across a wide range of study programmes andcourses at the Bachelor’s, Master’s and Doctoral level. Our study programmes stand on a tradition going back more than 165 years, but reflect current, state of the art technologies and the needs of industry and society.";
            string messageEncrypted = ""; //DataOperationsCrypto.DoCrypto(secretMessage); //mock
            Dictionary<int, string> stegoMethods = NetSteganography.GetListOfStegoMethods();

            //config local
            string ipSource = ConsoleTools.SelectInterface();
            //ushort port = 11000;

            //config remote
            string ipremote = "192.168.1.150";
            ushort portremote = 11001;

            if (String.Equals("s", role)) //its server
            {
                //prepare server
                NetReceiverServer rs = new NetReceiverServer(ipSource);
                //rs.Secret = secretMessage; //client!
                rs.StegoMethod = stegoMethods[31]; //needs to know because of reply
                rs.IpDestinationInput = ipremote;
                rs.PortDestination = portremote;

                //TODO offer run of another client
                System.Console.WriteLine("\nDo you want to run client on same device? (y/n) n");

                //prepare thread for server
                ThreadStart threadDelegate = new ThreadStart(rs.Listening);
                Thread receiverServerThread = new Thread(threadDelegate);
                //Thread receiverServerThread = new Thread(rs.Listening);
                receiverServerThread.Name = "ListeningAndReceivingThread";
                receiverServerThread.Start();
                receiverServerThread.IsBackground = true;

                //server activity output
                System.Console.WriteLine("\nShowing server running information. Press ESC to stop when message is received.");
                do
                {
                    while (!System.Console.KeyAvailable)
                    {
                        ConsoleTools.writeInfoConsole(rs);
                    }
                } while (System.Console.ReadKey(true).Key != ConsoleKey.Escape);
                
                rs.terminate = true;
                receiverServerThread.Abort(); //stop server thread
                receiverServerThread.Join();

                messageEncrypted = rs.GetSecretMessage();
                messageReadable = DataOperationsCrypto.ReadCrypto(messageEncrypted); //mock

                System.Console.WriteLine(String.Format("Received secret message is: {0}", messageReadable));                
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
