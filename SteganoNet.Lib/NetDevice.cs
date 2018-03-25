using PcapDotNet.Core;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.IpV4;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
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

            return null; //can be easily tested
            //return NetDevice.allDevices[0]; //working but very tricky
        }

        //L2        
        public static MacAddress GetRandomMacAddress() //used when ARP request fails
        {
            //TODO should be extended 
            //* read computer manufacturer https://social.msdn.microsoft.com/Forums/vstudio/en-US/4c8e8287-3898-4990-a81b-98f6432514b1/how-to-get-system-manufacturer-name-using-c?forum=csharpgeneral
            //* get some random mac http://www.gcstech.net/macvendor/index.php?node=vensea&list
            return new MacAddress("84:2B:2B:23:8C:AB");
        }

        //L3
        public static List<Tuple<string, string>> GetIPv4addressesAndDescriptionLocal() //pair of strings ipv4 and description for UI
        {
            List<Tuple<string, string>> result = new List<Tuple<string, string>>();
            foreach (string ipv4add in GetIPv4addressesLocal()) //get list of local IPv4 addresses from other method
            {
                try
                {
                    PacketDevice pd = GetSelectedDevice(new IpV4Address(ipv4add));
                    if (pd == null)
                        continue; //TODO TEST!

                    result.Add(new Tuple<string, string>(ipv4add, pd.Description));
                }
                catch
                {
                    //failing when freshly installed WinPcap and not 
                    //return null;
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
                result.Add("169.254.0.1"); //btw. highway to hell
                result.Add("127.0.0.1"); //btw. highway to hell

                //TODO implement system listing - not PcapDotNet, BUT this exception happens when: (dependency error)
                //System.TypeInitializationException: The type initializer for 'SteganoNetLib.NetDevice' threw an exception. --->System.IO.FileNotFoundException: Could not load file or assembly 'PcapDotNet.Core.dll' or one of its dependencies.The specified module could not be found.
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

    }
}
