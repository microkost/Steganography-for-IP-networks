using PcapDotNet.Packets;
using PcapDotNet.Packets.Ethernet;
using System;
using System.Collections.Generic;

namespace SteganoNetLib
{
    public interface INetNode
    {
        //contains common properties for common roles like Receiver or Sender
        //maybe should be removed for simplicity, not that huge ammout of shared code...

        //steganography parametres
        List<int> StegoUsedMethodIds { get; set; }
        string Secret { get; set; } //server dont need it actually...        

        //network parametres
        string IpSourceInput { get; set; } //not IpV4Address from PcapDotNet (references grow)
        //IpV4Address SourceIP { get; set; } //internal format
        string IpDestinationInput { get; set; } //server not need it 
        //IpV4Address DestinationIP { get; set; } //internal format
        ushort PortDestination { get; set; }
        ushort PortSource { get; set; }
        MacAddress MacAddressSource { get; set; }
        MacAddress MacAddressDestination { get; set; }

        //control
        Queue<string> messages { get; set; }
        //bool terminate { get; set; }

        //methods
        string GetSecretMessage(); //no access to Packets obj because of referencies... GetSecretMessage(List<Tuple<Packet, String>> MessageIncluded)
    }    
}
