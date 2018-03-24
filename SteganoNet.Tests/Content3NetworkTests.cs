using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SteganoNetLib;
using PcapDotNet.Packets.IpV4;

namespace SteganoNet.Tests
{
    public class Content3NetworkTests
    {
        //TODO compare input with output of SetContent3Network vs GetContent3Network
        [TestMethod]
        public void Content3NetworkTest()
        {
            string binSource = "0100100001100101011011000110110001101111001000000111011101101111011100100110110001100100";
            //do { }

            //its not done yet

            //regular operation
            List<int> methodsIds = NetSteganography.GetListMethodsId(NetSteganography.NetworkRangeStart, NetSteganography.NetworkRangeEnd, NetSteganography.GetListStegoMethodsIdAndKey()); //selected all existing int ids in range of IP codes
            Tuple<IpV4Layer, string> actual = SteganoNetLib.NetSteganography.SetContent3Network(SteganoNetLib.NetStandard.GetIpV4Layer(new IpV4Address("127.0.0.1"), new IpV4Address("127.0.0.1")), methodsIds, binSource);
            
            //string expected = SteganoNetLib.NetSteganography.GetContent3Network(actual.Item1, methodsIds);
            
            Assert.AreEqual(/*expected*/"", binSource);
        }
    }
}
