using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Ethernet;

namespace SteganoNetLib
{
    public class NetSenderClient : INetNode
    {
        //public string StegoMethod { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public List<int> StegoUsedMethodIds { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public string Secret { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public string IpSourceInput { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public string IpDestinationInput { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public ushort PortDestination { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public ushort PortSource { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public MacAddress MacAddressSource { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public MacAddress MacAddressDestination { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public Queue<string> messages { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        

        private string GetSecretMessage(List<Tuple<Packet, string>> MessageIncluded)
        {
            return "NotImplementedException";
        }
        public string GetSecretMessage()
        {
            //return GetSecretMessage(this.StegoPackets);
            return "NotImplementedException";
        }
    }
}
