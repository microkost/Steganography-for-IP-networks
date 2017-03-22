using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.IpV4;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace SteganographyFramework
{
    public static class NetworkMethods
    {
        //---------L2------------------------------------------------------------------------------------------------------------
        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        private static extern int SendARP(int DestIP, int SrcIP, byte[] pMacAddr, ref uint PhyAddrLen);
        public static string GetMacAddress(string ipAddress) //system method, not from PcapDotNet
        {
            //source: https://stephenhaunts.com/2014/01/06/getting-the-mac-address-for-a-machine-on-the-network/

            if (string.IsNullOrEmpty(ipAddress))
            {
                return null;
            }

            IPAddress IP = IPAddress.Parse(ipAddress);
            byte[] macAddr = new byte[6];
            uint macAddrLen = (uint)macAddr.Length;

            if (SendARP((int)IP.Address, 0, macAddr, ref macAddrLen) != 0)
            {
                return null;
            }

            string[] str = new string[(int)macAddrLen];

            for (int i = 0; i < macAddrLen; i++)
            {
                str[i] = macAddr[i].ToString("x2");
            }

            return string.Join(":", str).ToUpper();
        }
        public static MacAddress getDestinationMacAddress(IpV4Address ipAddress) //because destination mac address needs to be requested for network
        {
            if (ipAddress == null) //in case of input problem
            {
                ipAddress = new IpV4Address(GetDefaultGateway().ToString()); //get alternative default gateway ip
            }

            MacAddress macAddress;

            try
            {
                macAddress = new MacAddress(GetMacAddress(ipAddress.ToString())); //get L2 destination address for inserted IP address
            }
            catch
            {
                macAddress = new MacAddress("02:02:02:02:02:02");

            }

            return macAddress;
        }
        public static EthernetLayer GetEthernetLayer(MacAddress MacAddressSource, MacAddress MacAddressDestination)
        {
            EthernetLayer ethernetVrstva = new EthernetLayer();
            ethernetVrstva.Source = MacAddressSource;
            ethernetVrstva.Destination = MacAddressDestination;
            ethernetVrstva.EtherType = EthernetType.None; //Will be filled automatically.                            
            return ethernetVrstva;
        }

        //---------L3------------------------------------------------------------------------------------------------------------
        public static IpV4Layer GetIpV4Layer(IpV4Address SourceIP, IpV4Address DestinationIP) //(IpV4Protocol carryingLayer)
        {
            IpV4Layer ipv4Vrstva = new IpV4Layer();
            ipv4Vrstva.TypeOfService = Convert.ToByte(0); //STEGO ready //0 default value
            ipv4Vrstva.Source = SourceIP;
            ipv4Vrstva.CurrentDestination = DestinationIP; //ipv4Vrstva.Destination is read only
            ipv4Vrstva.Fragmentation = IpV4Fragmentation.None;
            ipv4Vrstva.HeaderChecksum = null; //Will be filled automatically.
            ipv4Vrstva.Identification = 1;
            ipv4Vrstva.Options = IpV4Options.None;
            ipv4Vrstva.Ttl = 128;

            /*
            if (carryingLayer == IpV4Protocol.Tcp)
                ipv4Vrstva.Protocol = IpV4Protocol.Tcp; //set ISN

            if (carryingLayer == IpV4Protocol.Udp)
                ipv4Vrstva.Protocol = IpV4Protocol.Udp;

            if (carryingLayer == IpV4Protocol.UdpLite)
                ipv4Vrstva.Protocol = IpV4Protocol.UdpLite;
            */

            return ipv4Vrstva;
        }

        public static IpV4Address GetDefaultGateway() //returns default gateway from system, not from PcapDotNet
        {
            //source: http://stackoverflow.com/questions/13634868/get-the-default-gateway

            IPAddress result = null;
            var cards = NetworkInterface.GetAllNetworkInterfaces().ToList();
            if (cards.Any())
            {
                foreach (var card in cards)
                {
                    var props = card.GetIPProperties();
                    if (props == null)
                        continue;

                    var gateways = props.GatewayAddresses;
                    if (!gateways.Any())
                        continue;

                    var gateway =
                        gateways.FirstOrDefault(g => g.Address.AddressFamily.ToString() == "InterNetwork");
                    if (gateway == null)
                        continue;

                    result = gateway.Address;
                    break;
                };
            }

            string address = result.ToString();
            IpV4Address ipv4address = new IpV4Address(address);
            return ipv4address;
        }

        //---------L4------------------------------------------------------------------------------------------------------------
        //---------L5------------------------------------------------------------------------------------------------------------
        //---------L6------------------------------------------------------------------------------------------------------------
        //---------L7------------------------------------------------------------------------------------------------------------
    }
}
