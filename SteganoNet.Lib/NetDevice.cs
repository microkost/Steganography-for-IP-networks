using PcapDotNet.Core;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.IpV4;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace SteganoNetLib
{
    public static class NetDevice //class with service methods for THIS local hardware device
    {
        //general
        public static IList<LivePacketDevice> allDevices = LivePacketDevice.AllLocalMachine; //list of available devices               

        public static PacketDevice GetSelectedDevice(IpV4Address ipOfInterface)
        {
            string tmpIp = ipOfInterface.ToString(); //nessesary for lookup method below

            try
            {
                foreach (LivePacketDevice lpd in allDevices)
                {
                    foreach (DeviceAddress nonparsed in lpd.Addresses)
                    {
                        string[] words = nonparsed.ToString().Split(' ');

                        if (String.Equals(words[2], tmpIp)) //should be more effective by filtering IPv6 out
                        {
                            return lpd; //return device with requested IP
                        }
                    }
                }
            }
            catch
            {
                return null; //can be easily tested
            }

            return null; //can be easily tested
        }

        //L2        
        public static MacAddress GetRandomMacAddress() //used when ARP request fails
        {
            //TODO should be extended 
            //* read computer manufacturer https://social.msdn.microsoft.com/Forums/vstudio/en-US/4c8e8287-3898-4990-a81b-98f6432514b1/how-to-get-system-manufacturer-name-using-c?forum=csharpgeneral
            //* get some mac based on manufacturer http://www.gcstech.net/macvendor/index.php?node=vensea&list
            return new MacAddress("84:2B:2B:23:8C:AB");
        }

        public static MacAddress? GetLocalMacAddress(IpV4Address ipv4Address) //getting local mac address from powershell
        {
            try
            {
                Process p = new Process();
                p.StartInfo.UseShellExecute = false;
                p.StartInfo.RedirectStandardOutput = true;
                p.StartInfo.FileName = "powershell.exe";
                p.StartInfo.Arguments = String.Format("Get-WmiObject win32_networkadapterconfiguration | Where-Object {{$_.IPAddress -eq '{0}'}} | select macaddress", ipv4Address.ToString());
                p.Start();

                string output = p.StandardOutput.ReadToEnd();
                p.WaitForExit();

                string[] stringSeparators = new string[] { "\r\n" };
                string[] parsedDirty = output.Split(stringSeparators, StringSplitOptions.None);

                List<MacAddress> macList = new List<MacAddress>();
                foreach (string s in parsedDirty) //checking and cleaning of strings
                {
                    string mac = s.Trim();
                    Regex regex = new Regex("^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}|(?:[0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}|(?:[0-9a-fA-F]{2}){5}[0-9a-fA-F]{2}$", RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.Multiline);
                    MatchCollection mc = regex.Matches(mac); //saving only those which are looking like mac...
                    foreach (Match m in mc)
                    {
                        macList.Add(new MacAddress(mac));
                    }
                }
                return macList.First();
            }
            catch
            {
                return null;
            }
        }

        //L3
        public static List<Tuple<string, string>> GetIPv4addressesAndDescriptionLocal() //pair of strings ipv4 and description for UI
        {
            List<Tuple<string, string>> result = new List<Tuple<string, string>>();
            List<string> ipv4AddresesLocal = GetIPv4addressesLocal();

            try
            {
                foreach (string ipv4add in ipv4AddresesLocal) //get list of local IPv4 addresses from other method
                {
                    PacketDevice pd = GetSelectedDevice(new IpV4Address(ipv4add));
                    if (pd == null)
                    {
                        continue; //TODO TEST!
                    }
                    result.Add(new Tuple<string, string>(ipv4add, pd.Description));
                }
            }
            catch
            {
                //failing when PcapDotNet library is failing OR running on virtual machine
                if (ipv4AddresesLocal.Count < 1)
                {
                    result.Add(new Tuple<string, string>("0.0.0.0", "Interface is product of internal error"));
                }
                else
                {
                    foreach (string ipv4add in ipv4AddresesLocal)
                    {
                        result.Add(new Tuple<string, string>(ipv4add, "no description available, backup method used"));
                    }
                }
            }

            return result;
        }

        public static List<string> GetIPv4addressesLocal() //return available list of IP addresses
        {
            List<String> result = new List<String>(); //TODO should be List<IpV4Address>

            try
            {
                foreach (LivePacketDevice lpd in allDevices)
                {
                    foreach (DeviceAddress nonparsed in lpd.Addresses) //try-catch needed?
                    {
                        string tmp = nonparsed.ToString();
                        string[] words = tmp.Split(' '); //string: Address: Internet 192.168.124.1 Netmask: Internet 255.255.255.0 Broadcast: Internet 0.0.0.0

                        if (words[1] == "Internet6")
                        {
                            //print String.Format("IPv6 skipped\r\n");
                        }

                        if (words[1] == "Internet")
                        {
                            result.Add(words[2]);
                        }
                    }
                }
            }
            catch
            {
                try //system listing - not PcapDotNet 
                {
                    var host = Dns.GetHostEntry(Dns.GetHostName()); //this is not tested!
                    foreach (var ip in host.AddressList)
                    {
                        if (ip.AddressFamily == AddressFamily.InterNetwork)
                        {
                            result.Add(ip.ToString());
                        }
                    }
                    System.Console.WriteLine("Backup solution applied, listing IP addreses localy.");
                }
                catch
                {
                    result.Add("0.0.0.0"); //highway to hell
                    result.Add("127.0.0.1"); //highway to hell
                    result.Add("169.254.0.1"); //highway to hell                                       
                }
            }

            return result;
        }

        //L4

        //L7
        public static List<string> GetDomainsForDnsRequest(bool fromStatic = false) //getting DNS hostnames from local DNS cache or hardcoded
        {
            List<string> domainsToRequest = new List<string>();

            if (!fromStatic)
            {
                try //source: https://stackoverflow.com/questions/206323/how-to-execute-command-line-in-c-get-std-out-results
                {
                    Process p = new Process();
                    p.StartInfo.UseShellExecute = false;
                    p.StartInfo.RedirectStandardOutput = true;
                    p.StartInfo.FileName = "powershell.exe";
                    p.StartInfo.Arguments = "Get-DNSClientCache | select name";
                    p.Start();

                    string output = p.StandardOutput.ReadToEnd();
                    p.WaitForExit();

                    string[] stringSeparators = new string[] { "\r\n" };
                    string[] parsedDirty = output.Split(stringSeparators, StringSplitOptions.None);

                    foreach (string s in parsedDirty) //checking and cleaning of strings
                    {
                        //saving only those which are looking like domain name...
                        string domainName = s.Trim();
                        Regex regex = new Regex("^((http://)|(https://))*([a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,6}[/]*", RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.Multiline);
                        MatchCollection mc = regex.Matches(domainName);
                        foreach (Match m in mc)
                        {
                            domainsToRequest.Add(domainName);
                        }
                    }

                    if (domainsToRequest.Count < 1) //just in case
                    {
                        fromStatic = true;
                    }
                }
                catch
                {
                    fromStatic = true;
                }
            }

            if (fromStatic) //hardcoded solution
            {
                domainsToRequest = new List<String>() { "vsb.cz", "seznam.cz", "google.com", "yahoo.com", "github.com", "jamk.fi", "uwasa.fi", "microsoft.com", "yr.no", "googlecast.com" };
            }

            return (from dtr in domainsToRequest select dtr).Distinct().ToList(); //if ducplicate then remove one of them
        }

        public static bool CheckURLValid(this string source)
        {
            //TODO needed?
            return Uri.TryCreate(source, UriKind.Absolute, out Uri uriResult) && uriResult.Scheme == Uri.UriSchemeHttp;
        }

        public static List<string> GetSocialMediaDomains(bool fromStatic = true) //getting social media hostnames to 
        {
            //if (fromStatic) //hardcoded solution (random things could generate)
            List<string> services = new List<string>()
            {
                //always ends with "/"
                //parsing starting after second "/", keep two slashes in url after domain
                "https://scontent-arn2-1.xx.fbcdn.net/v/t1.0-9/",
                "https://scontent-arn2-1.xx.fbcdn.net/v/t31.0-8/",
                "https://www.facebook.com/groups/photos/", //groups should be username
                "https://scontent-arn2-1.cdninstagram.com/vp/t51.2885-15/",
                "https://scontent-arn2-1.cdninstagram.com/vp/5B74D9C8/",
                "https://pbs.twimg.com/media/DUj28A/",
                "https://pbs.twimg.com/media/DZ-5xFDU0/",
                "https://lh3.googleusercontent.com/UJbNrdoCmeA/Ws7miuqLMuI/",
                "https://lh3.googleusercontent.com/proxy/DFRhoqce1yHrzurt/",
                "https://lh3.googleusercontent.com/EEkBjHI/X0EEkBjH/",
                "https://img.washingtonpost.com/rf/image_1484w/"
            };

            //facebook
            //https://scontent-arn2-1.xx.fbcdn.net/v/t1.0-9/28783581_20442955785459_4786842833526980608_o.jpg?_nc_cat=0&oh=f393eabff543c001a7d549a606cd72&oe=5B3439EE
            //https://scontent-arn2-1.xx.fbcdn.net/v/t31.0-8/26756412_20106211617762_79826838983831551_o.jpg?_nc_cat=0&oh=1fe51c45d8053ae7b0f570763e3cfd&oe=5B729DA3
            //https://www.facebook.com/<username>/photos/a.16932240891429.1073741827.1693231710891882/20424925969557/?type=3&theater
            //instagram                                
            //https://scontent-arn2-1.cdninstagram.com/vp/8c1b8efbaac6831e25d59e6a047276/5B6D8993/t51.2885-15/e35/29417270_195771601230887_30806938333020160_n.jpg
            //https://scontent-arn2-1.cdninstagram.com/vp/d9d046183c558e2065c6b77ded7cd8/5B74D9C8/t51.2885-15/e35/29417740_596673960668154_56338044696838144_n.jpg
            //twitter
            //https://pbs.twimg.com/media/DUj28AkAEy8q7.jpg:large
            //https://pbs.twimg.com/media/DZ-5xF0AAJRPu.jpg:large
            //google plus / picasa
            //https://lh3.googleusercontent.com/-UJbNrdoCmeA/Ws7miuqLMuI/AAAAAAAALLg/8_bZH7ZEKz8SLRG1fo7evhDeaTdzIAPsQCJoC/w530-h663-n-rw/The%2BInner%2BCircle.jpg            
            //https://lh3.googleusercontent.com/proxy/-DFRhoqce1yHrzurtSyOjUEV23ty9q4aur7qJFRH54IvUpavBjFMSNqM8eEiNRQPq1C58EkvJpaXcbTHPjTT8YrQcYQYfTSe-zzcq9KL_ics9BUXXZUzu2Oq=w265-h177-p-rw
            //https://lh3.googleusercontent.com/proxy/88h-zgjP7hnhVBA9onuox1RbsMAVWTOI7keYBRpQ2OVo6QVB1lEy4rHgmJVI3339JmEoPu9Wza21YpHucAIdS9uiz78M_hbXl9jJK1Ws6FqKkGQqSkLCEb2ymiaGSyvvWwOovw_0L7_sxhjjGto=w265-h177-p-rw
            //https://lh3.googleusercontent.com/proxy/X0EEkBjHI6sLAR2oQsJYKU4nL4ReNTEI8W1zCQ7J4ZnlhB8v8yyC7CWCa6-e9Qzn0K45pzFAAN0Iz8F99Hi3pyWFb-CaXT8PmX7lrIrbDCQpmH-x=w265-h171-p-rw
            //pinterest
            //random
            //https://img.washingtonpost.com/rf/image_1484w/2010-2019/WashingtonPost/2018/04/11/National-Politics/Images/Trump_09941.jpg-2d74f-4204.jpg?uuid=Bq6TcD3jEeiNU-ug7SNxzA


            return services;
        }

        public static List<string> GetSocialMediaSuffix(bool fromStatic = true) //getting social media append
        {
            //random things could generate

            //if (fromStatic) //hardcoded solution
            List<string> services = new List<string>()
            {
                "_o.jpg?_nc_cat=0&oh=f39",
                "_?type=3&theater",
                "_n.jpg?_nc_cat=1&oh=b0f95763e3cfd&oe=5B729DA3",
                "_n.jpg:large",
                ".jpg:large",
                ".png?GSyvvWwOovw_0L7_sxhjjGto=w265-h177-p-rw",
                ".jpg:small?",
                ".jpg?uuid=Bq6TcD3jEeiNU-ug7SNxzA"
            };
            return services;
        }
    }
}