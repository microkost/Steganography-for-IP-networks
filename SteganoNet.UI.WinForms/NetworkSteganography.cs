using PcapDotNet.Base;
using PcapDotNet.Core;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Dns;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.Http;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.Transport;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;
using System.Diagnostics;

namespace Steganography
{
    public struct datagram
    {
        public EthernetLayer l2;
        public IpV4Layer l3;
    };
    public static class NetworkSteganography
    {




        //---------L3------------------------------------------------------------------------------------------------------------

        public static datagram StegoL3ipid()
        {
            return new datagram(); //totally working
        }

        //IP method 1 - most transparent - using Identification field and changing it every two minutes accoring to standard - iteration of value 

        //IP method X - offset number like TTL lower, smth constant is under or value is unmasked... IF allowed!

        //IP method 2 - maximum method (method 1 + usage of flags + fragment offset + 

        //ip method 3 - transparent - count TTL and use some value under as rest...

        //IP method 4 - TypeOfService fild - extrely lame way but... Usage high bits 6 + 7 is "OK"...

        //IP method 5  - 



        
    }
}
