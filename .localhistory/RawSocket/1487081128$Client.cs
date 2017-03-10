using PcapDotNet.Core;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RawSocket
{
    public class Client
    {
        public volatile bool terminate = false;
        public string tmpIp { get; set; }
        public string StegoMethod { get; set; } //contains name of choosen method
        public string Secret { get; set; } //contains magic to be transferred
        public void Speaking()
        {
            Lib.selectedDevice = Lib.allDevices[Lib.getSelectedInterfaceIndex(tmpIp)]; // Take the selected adapter

            //name of the device //size // promiscuous mode // read timeout
            using (PacketCommunicator communicator = Lib.selectedDevice.Open(100, PacketDeviceOpenAttributes.Promiscuous, 1000))
            {
                
                if (String.Equals(StegoMethod, "ICMP payload"))
                {

                }
                else if (String.Equals(StegoMethod, "IPv4 manipulation"))
                {

                }
                else if (String.Equals(StegoMethod, "TCP manipulation"))
                {
                    /* ODSTAVENO, bude složit pro modifikaci, standardní funkce BuildCOSIG by měly posílat korektní packety, zde se případně postaví speciality v nějakém cyklu a vloží se do standardních vrstev
                    TcpLayer tcpLayer = new TcpLayer
                    {
                        SourcePort = UInt16.Parse(numericUpDownClientPort.Value.ToString()),
                        DestinationPort = UInt16.Parse(numericUpDownServerPort.Value.ToString()),
                        Checksum = null, // Will be filled automatically.
                        SequenceNumber = 20170213,
                        ControlBits = TcpControlBits.Acknowledgment,
                        UrgentPointer = 0,
                        Options = TcpOptions.None,
                    };

                    PayloadLayer payloadLayer = new PayloadLayer
                    {
                        Data = new Datagram(Encoding.ASCII.GetBytes("hello world")),
                    };

                    PacketBuilder builder = new PacketBuilder(tcpLayer, payloadLayer);  //Additional information: First layer (PcapDotNet.Packets.Transport.TcpLayer) must provide a DataLink
                    */

                    communicator.SendPacket(BuildTcpPacket(textBoxSecret.Text));

                }
                else
                {
                    textBoxSecret.Text = "Nothing happened";
                }
            }
        }
    }
}
