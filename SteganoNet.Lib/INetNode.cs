using PcapDotNet.Packets;
using PcapDotNet.Packets.Ethernet;
using System;
using System.Collections.Generic;

namespace SteganoNetLib
{
    public interface INetNode
    {
        //contains common properties for common roles like Receiver or Sender        

        //steganography parametres
        List<int> StegoUsedMethodIds { get; set; }

        //network parametres
        string IpLocalString { get; set; } //not IpV4Address from PcapDotNet (reference izolation)        
        string IpRemoteString { get; set; } //server not need it         
        ushort PortLocal { get; set; }
        ushort PortRemote { get; set; }
        MacAddress MacAddressLocal { get; set; }
        MacAddress MacAddressRemote { get; set; }

        //control
        Queue<string> Messages { get; set; }
        //bool Terminate { get; set; } //ends thread, doesnt work because is not property - volatile used

        //methods
        bool ArePrerequisitiesDone(); //checking if properties are not null before start
        void AddInfoMessage(string txt); //add something to output from everywhere else...        
    }
}
