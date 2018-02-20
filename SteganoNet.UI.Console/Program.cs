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
            //*select role (server / client)
            //*select network interface
            //*choose network parametres
            //*choose steganographic method
            //*add instance of client or server (debug and testing purposes), end if
            //run
            //view immediate info
            //stop
            //analyze results

            System.Console.WriteLine("Welcome in Steganography for IP networks tool.\n");
            if (SteganoNet.Lib.SystemCheck.AreSystemPrerequisitiesDone() == false) //can run?
            {
                System.Console.WriteLine("Nessesary library WinPcap is not installed or PcapDotNet is not present. Check it please and restart.");
                System.Console.WriteLine("Press any key to exit... ");
                System.Console.ReadKey();
                return;
            }

            //config global (pre-initialization)
            string role = "s"; //server or client
            string messageReadable = ""; //filled by client later
            string messageEncrypted = DataOperationsCrypto.DoCrypto(messageReadable);            
            List<int> stegoMethods = new List<int>();
            System.Diagnostics.Process secondWindow = null; //testing solution on same computer
            string runSame = "n"; //user answer for same device

            //network values (pre-initialization)
            string ipSource = "0.0.0.0";
            ushort portSource = NetStandard.GetAvailablePort(11000);
            string ipRemote = "0.0.0.0";
            ushort portRemote = NetStandard.GetAvailablePort(11011);

            if (args.Length == 0 || args == null) //no user parametrized input = configuration WIZARD
            {
                System.Console.WriteLine("Do you want to run configuration wizard? (y/n) y"); //ha-ha             
                System.Console.WriteLine("\tUse IPv4 or IPv6? (4/6) 4"); //ha-ha

                System.Console.Write("\tIs this device (s)erver-receiver or (c)lient-sender? (s/c) ");
                role = System.Console.ReadLine();
                System.Console.WriteLine("");

                //local IP
                ipSource = ConsoleTools.SelectInterface(); //interactive
                System.Console.WriteLine("");

                //local port                
                System.Console.Write(String.Format("\tEnter source port: should it be {0}? (y or enter / number) ", portSource));
                string portSourceNotParsed = System.Console.ReadLine();
                if (portSourceNotParsed.StartsWith("y") || String.IsNullOrWhiteSpace(portSourceNotParsed)) //not default answer
                {
                    System.Console.WriteLine(String.Format("\t\tUsed port is: {0}", portSource)); //without change
                }
                else
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
                uint byte4 = Convert.ToUInt32(ipBytes[3]) + 0;
                ipRemote = String.Format("{0}.{1}.{2}.{3}", byte1, byte2, byte3, byte4);
                System.Console.Write(String.Format("\tEnter remote host IP address: should it be {0}?  (y or enter / ip address) ", ipRemote));
                string ipremoteNotParsed = System.Console.ReadLine();
                if (ipremoteNotParsed.StartsWith("y") || String.IsNullOrWhiteSpace(ipremoteNotParsed)) //not default answer
                {
                    System.Console.WriteLine(String.Format("\t\tUsed remote ip is: {0}", ipRemote)); //without change
                }
                else
                {
                    if (System.Net.IPAddress.TryParse(ipremoteNotParsed.ToString(), out System.Net.IPAddress parsed))
                    {
                        ipRemote = parsed.ToString();
                    }
                    System.Console.WriteLine(String.Format("\t\tUsed remote ip is: {0}", ipRemote));
                }

                //remote port
                System.Console.Write(String.Format("\tEnter remote port: should it be {0}? (y or enter / number) ", portRemote));
                string portRemoteNotParsed = System.Console.ReadLine();
                if (portRemoteNotParsed.StartsWith("y") || String.IsNullOrWhiteSpace(portRemoteNotParsed)) //not default answer
                {
                    System.Console.WriteLine(String.Format("\t\tUsed port is: {0}", portRemote)); //without change
                }
                else
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
                //System.Console.WriteLine("");
            }
            else //skip the wizard, source from parametres
            {
                System.Console.WriteLine("Do you want to run configuration wizard? (y/n) n\n\nUsing following parametres as settings: ");
                /*
                 * VALID PARAMS: (separator is space)
                 * -role client 
                 * -ip 192.168.1.216 
                 * -port 11011 
                 * -ipremote 192.168.1.216
                 * -portremote 11001;
                 * -methods: TODO!
                 * -runsame: n
                 */
                
                for (int i = 0; i < args.Length; i++)
                {                    
                    switch (args[i])
                    {                        
                        case "-role":
                            {
                                i++;
                                if (args.Length <= i) throw new ArgumentException(args[i]);
                                role = args[i].Substring(0, 1).ToLower(); //first char only
                                break;
                            }

                        case "-ip":
                            {
                                i++;
                                if (args.Length <= i) throw new ArgumentException(args[i]);
                                ipSource = args[i];
                                break;
                            }
                        case "-port":
                            {
                                i++;
                                if (args.Length <= i) throw new ArgumentException(args[i]);
                                ushort.TryParse(args[i].ToString(), out ushort parsed); //parsing
                                portSource = parsed;
                                break;
                            }
                        case "-ipremote":
                            {
                                i++;
                                if (args.Length <= i) throw new ArgumentException(args[i]);
                                ipRemote = args[i];
                                break;
                            }
                        case "-portremote":
                            {
                                i++;
                                if (args.Length <= i) throw new ArgumentException(args[i]);
                                ushort.TryParse(args[i].ToString(), out ushort parsed); //parsing
                                portRemote = parsed;
                                break;
                            }
                        case "-methods":
                            {
                                i++;
                                //TODO reasemble list
                                break;
                            }
                        case "-runsame":
                            {
                                i++;
                                if (args.Length <= i) throw new ArgumentException(args[i]);
                                runSame = args[i].Substring(0, 1).ToLower(); //first char only
                                break;
                            }
                    }
                    System.Console.WriteLine(String.Format("\t{0} value: {1}", args[i-1], args[i]));
                }                
            }

            if (String.Equals("s", role)) //its server
            {
                //prepare server
                NetReceiverServer rs = new NetReceiverServer(ipSource, portSource);
                rs.StegoUsedMethodIds = stegoMethods;
                rs.IpDestinationInput = ipRemote;
                rs.PortDestination = portRemote;

                //offers running client
                System.Console.Write("\nDo you want to run client on same device for testing? (y/n) ");
                runSame = System.Console.ReadLine();
                if (runSame.StartsWith("y") || runSame.StartsWith("Y"))
                {
                    string arguments = String.Format("-role client -ip {0} -port {1} -ipremote {2} -portremote {3} -methods {4} -runsame {5}", ipRemote, portRemote, ipSource, portSource, string.Join(",", stegoMethods.Select(n => n.ToString()).ToArray()), "n"); //inverted settings
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
                sc.IpDestinationInput = ipRemote;
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
