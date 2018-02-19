using SteganoNetLib;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;

namespace SteganoNet.UI.Console
{
    public class Program
    {
        static void Main(string[] args) //static removed
        {
            //method flow:
            //check sw dependencies
            //recognize mode (parametres / wizard), if wizard then:
            //select role (server / client)
            //select network interface
            //choose network parametres
            //choose steganographic method
            //add instance of client or server (debug and testing purposes), end if
            //run
            //view immediate info
            //stop
            //analyze results

            System.Console.WriteLine("Welcome in Steganography for IP networks tool.\n"); //some more epic entrance http://patorjk.com/software/taag/#p=display&f=Crawford2&t=Stegano-IP                      
            if (SteganoNet.Lib.SystemCheck.AreSystemPrerequisitiesDone() == false) //just to be obvious
            {
                System.Console.WriteLine("Nessesary library WinPcap is not installed or PcapDotNet is not present. Check it please and restart.");
                System.Console.WriteLine("Press any key to exit... ");
                System.Console.ReadKey();
                return;
            }

            //config global
            string role = "s"; //server or client
            string messageReadable = ""; //filled by client or server after receiving
            string messageEncrypted = DataOperationsCrypto.DoCrypto(messageReadable);
            System.Diagnostics.Process secondWindow = null; //testing solution on same computer
            List<int> stegoMethods = new List<int>();

            //config local            
            string ipSource = "0.0.0.0";
            ushort portSource = NetStandard.GetAvailablePort(11000);

            //config remote
            string ipremote = "0.0.0.0"; //TODO ASK USED
            ushort portRemote = NetStandard.GetAvailablePort(11011);

            if (args.Length == 0 || args == null) //no user parametrized input = configuration WIZARD
            {
                System.Console.WriteLine("Do you want to run configuration wizard? (y/n) y"); //ha-ha             
                System.Console.WriteLine("\tUse IPv4 or IPv6? (4/6) 4"); //hardcoded

                System.Console.Write("\tIs this device (s)erver-receiver or (c)lient-sender? (s/c) ");
                role = System.Console.ReadLine();
                System.Console.WriteLine("");

                //local IP
                ipSource = ConsoleTools.SelectInterface(); //interactive
                System.Console.WriteLine("");

                //local port
                System.Console.Write(String.Format("\tEnter source port: should it be {0}? (y/number) ", portSource));
                string portSourceNotParsed = System.Console.ReadLine();
                if (!portSourceNotParsed.StartsWith("y")) //not default answer
                {
                    if (!ushort.TryParse(portSourceNotParsed.ToString(), out ushort parsed))
                    {
                        portSource = NetStandard.GetAvailablePort(48000);
                    }
                    else
                    {
                        portSource = parsed;
                    }
                    System.Console.WriteLine(String.Format("\t\tUsed port is: {0}", portSource));
                }                

                //remote IP address
                String[] ipBytes = ipSource.Split('.'); uint byte1 = Convert.ToUInt32(ipBytes[0]); uint byte2 = Convert.ToUInt32(ipBytes[1]); uint byte3 = Convert.ToUInt32(ipBytes[2]);
                uint byte4 = Convert.ToUInt32(ipBytes[3]) + 1;
                ipremote = String.Format("{0}.{1}.{2}.{3}", byte1, byte2, byte3, byte4);
                System.Console.Write(String.Format("\tEnter remote host IP address: should it be {0}? (y/ip address) ", ipremote));
                string ipremoteNotParsed = System.Console.ReadLine();
                if (!ipremoteNotParsed.StartsWith("y")) //not default answer
                {
                    if (System.Net.IPAddress.TryParse(ipremoteNotParsed.ToString(), out System.Net.IPAddress parsed))
                    {
                        ipremote = parsed.ToString();
                    }
                    System.Console.WriteLine(String.Format("\t\tUsed remote ip is: {0}", ipremote));
                }                

                //remote port
                System.Console.Write(String.Format("\tEnter remote port: should it be {0}? (y/number) ", portRemote));
                string portRemoteNotParsed = System.Console.ReadLine();
                if (!portRemoteNotParsed.StartsWith("y")) //not default answer
                {
                    if (!ushort.TryParse(portRemoteNotParsed.ToString(), out ushort parsed))
                    {
                        portRemote = NetStandard.GetAvailablePort(48000);
                    }
                    else
                    {
                        portRemote = parsed;
                    }
                    System.Console.WriteLine(String.Format("\t\tUsed port is: {0}", portRemote));
                }
                System.Console.WriteLine("");                

                stegoMethods = ConsoleTools.SelectStegoMethods(); //which methods are used (interactive)                
                System.Console.WriteLine("");
            }
            else //skip the wizard, source from parametres
            {
                System.Console.WriteLine("Do you want to run configuration wizard? (y/n) n\nUsing following parametres as settings: ");

                System.Console.WriteLine("Received settings: ");
                foreach (string arg in args)
                {
                    System.Console.WriteLine(String.Format("\targ: {0}", arg));
                    //TODO PARSING parametres
                }
                role = "s"; //DEBUG TMP
            }

            if (String.Equals("s", role)) //its server
            {
                //prepare server
                NetReceiverServer rs = new NetReceiverServer(ipSource, portSource);
                rs.StegoUsedMethodIds = stegoMethods;
                rs.IpDestinationInput = ipremote;
                rs.PortDestination = portRemote;

                //offers running client
                System.Console.Write("\nDo you want to run client on same device for testing? (y/n) ");
                string runIt = System.Console.ReadLine();
                if (runIt.StartsWith("y") || runIt.StartsWith("Y"))
                {
                    string arguments = "superCoolIP SomeOtherAlreadyProvidedSettingsToMakeItFaster itsClient!";
                    secondWindow = System.Diagnostics.Process.Start(System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName, arguments);
                }

                //prepare thread for server
                ThreadStart threadDelegate = new ThreadStart(rs.Listening);
                Thread receiverServerThread = new Thread(threadDelegate);
                //Thread receiverServerThread = new Thread(rs.Listening);
                receiverServerThread.Name = "ListeningThread";
                receiverServerThread.IsBackground = true;
                receiverServerThread.Start();

                //server activity output
                System.Console.WriteLine("\nShowing server running information. Press ESC to stop when message is received.");
                do
                {
                    while (!System.Console.KeyAvailable)
                    {
                        ConsoleTools.WriteInfoConsole(rs);
                    }
                } while (System.Console.ReadKey(true).Key != ConsoleKey.Escape);

                rs.terminate = true;
                receiverServerThread.Abort(); //stop server thread
                receiverServerThread.Join(); //needed?

                messageEncrypted = rs.GetSecretMessage();
                messageReadable = DataOperationsCrypto.ReadCrypto(messageEncrypted); //mock

                System.Console.WriteLine("");
                System.Console.WriteLine(String.Format("Received secret message is: {0}", messageReadable));
            }
            else if (String.Equals("c", role)) //its client
            {
                //prepare client
                //messageReadable = "VSB - Technical University of Ostrava has long tradition in high quality engineering. Provides tertiary education in technical and economic sciences across a wide range of study programmes andcourses at the Bachelor’s, Master’s and Doctoral level. Our study programmes stand on a tradition going back more than 165 years, but reflect current, state of the art technologies and the needs of industry and society.";
                messageReadable = "VSB - Technical University of Ostrava has long tradition in high quality engineering.";
                //System.Console.Write(String.Format("\tEnter secret message: (like {0})", messageReadable));
                //messageReadable = System.Console.ReadLine();
                messageEncrypted = DataOperationsCrypto.DoCrypto(messageReadable); //mock

                NetSenderClient sc = new NetSenderClient(ipSource, portSource);
                sc.SecretReadable = messageEncrypted;
                sc.StegoUsedMethodIds = stegoMethods;
                sc.IpDestinationInput = ipremote;
                sc.PortDestination = portRemote;

                //TODO offers run server
                System.Console.Write("\nDo you want to run client on same device for testing? (y/n) n");



            }
            else //catch
            {
                System.Console.WriteLine("\nSorry, I didnt understand your commands. Start again...");
            }

            try //handling opened console windows
            {
                if (secondWindow != null)
                {
                    System.Console.WriteLine("\nWaiting for end of second window. Please close it manually.");
                }
                secondWindow.WaitForExit(); //correct ending of opened window
            }
            catch (NullReferenceException)
            {
                //System.Console.WriteLine("No another window opened...");
            }

            System.Console.WriteLine("\nThat's all! Thank you for using Steganography for IP networks tool. Press any key to exit...");
            System.Console.ReadKey();
        }
    }

}
