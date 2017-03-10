using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

using System.Runtime.InteropServices; //console
using System.Net.Sockets;
using System.Net;
using System.Threading;

using PcapDotNet.Core;
using PcapDotNet.Base;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Ethernet;

namespace RawSocket
{
    public partial class MainWindow : Form
    {
        //private TcpListener listener;
        private Thread serverThread;

        //private TcpClient client;
        //private Thread clientThread;

        private bool isServer = true;
        private bool isServerListening = false;

        public IList<LivePacketDevice> allDevices; //list of network interfaces
        PacketDevice selectedDevice = null; //which device will be used for communication

        public delegate void ParameterizedThreadStart(bool isServerListening);
        public MainWindow()
        {
            InitializeComponent();
            InitialProcedure();
        }

        public MainWindow(bool isServer)
        {
            InitializeComponent();
            this.isServer = isServer; //isServer == false then isClient
            InitialProcedure();
        }

        private void InitialProcedure()
        {
            if (isServer) //changing checkboxes
            {
                checkBoxServer.Checked = true;
                checkBoxClient.Checked = false;
            }
            else
            {
                checkBoxServer.Checked = false;
                checkBoxClient.Checked = true;
            }

            checkBoxServer.Checked = isServer;
            AllocConsole(); //console window

            //get devices
            allDevices = LivePacketDevice.AllLocalMachine;
            if (allDevices.Count == 0)
                textBoxDebug.Text += "No interfaces found! Make sure WinPcap is installed.\n";

            List<String> IPv4addresses = new List<String>();
            //IPv4addresses.Add("127.0.0.1"); //add localhost //DEBUG!

            int i = 0;
            foreach (LivePacketDevice lpd in allDevices)
            {
                if (lpd.Description != null)
                {
                    textBoxDebug.Text += String.Format("Interface #{0}: {1}\r\n", i, lpd.Description);
                }
                else
                {
                    textBoxDebug.Text += String.Format("Interface: #{0}: {1}\r\n", i, lpd.Name);
                }
                i++;

                foreach (DeviceAddress nonparsed in lpd.Addresses) //try-catch needed?
                {
                    string tmp = nonparsed.ToString();
                    string[] words = tmp.Split(' '); //Address: Internet 192.168.124.1 Netmask: Internet 255.255.255.0 Broadcast: Internet 0.0.0.0


                    if (words[1] == "Internet6")
                    {
                        textBoxDebug.Text += String.Format("IPv6 skipped\r\n");
                    }

                    if (words[1] == "Internet")
                    {
                        /* int result = 0; //just exists
                         * bool isIPv4 = int.TryParse(words[2].Substring(0, 1), out result);
                         * if(isIPv4)
                         */
                        IPv4addresses.Add(words[2]);
                        textBoxDebug.Text += String.Format("IPv4 {0}\r\n", IPv4addresses.Last());
                    }
                }
                textBoxDebug.Text += "----------------------------------------\r\n";
            }

            //IP addresses server      
            //comboBoxServerAddress.DataSource = Dns.GetHostEntry(Dns.GetHostName()).AddressList;
            BindingSource bs_servers = new BindingSource();
            bs_servers.DataSource = IPv4addresses;
            comboBoxServerAddress.DataSource = bs_servers;
            comboBoxServerAddress.SelectedIndex = 0;

            //IP addresses client
            //comboBoxClientAddress.DataSource = Dns.GetHostEntry(Dns.GetHostName()).AddressList;
            BindingSource bs_clients = new BindingSource();
            bs_clients.DataSource = IPv4addresses;
            comboBoxClientAddress.DataSource = bs_clients;
            comboBoxClientAddress.SelectedIndex = 0;

            //methods combobox (text is ID for method)
            List<String> methods = new List<String>();
            methods.Add("Pokus test");
            methods.Add("ICMP payload");
            methods.Add("ICMP tunnel");
            methods.Add("TCP steganography");
            methods.Add("Byte transfer");
            BindingSource bs_methods = new BindingSource();
            bs_methods.DataSource = methods;
            comboBoxMethod.DataSource = bs_methods;
            comboBoxMethod.SelectedIndex = 0;
        }

        //console window initialization
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool AllocConsole();

        private void Listening(bool isServerListening, string tmpIp)
        {

            selectedDevice = allDevices[selectedInterface(tmpIp)]; // Take the selected adapter

            if (isServerListening == false)
            {
                // Open the device // portion of the packet to capture // 65536 guarantees that the whole packet will be captured on all the link layers // promiscuous mode // read timeout
                using (PacketCommunicator communicator = selectedDevice.Open(65536, PacketDeviceOpenAttributes.Promiscuous, 1000))
                {
                    SettextBoxDebug(String.Format("Listening on {0}...", selectedDevice.Description));

                    // Retrieve the packets
                    Packet packet;
                    do
                    {
                        PacketCommunicatorReceiveResult result = communicator.ReceivePacket(out packet);
                        switch (result)
                        {
                            case PacketCommunicatorReceiveResult.Timeout:
                                // Timeout elapsed
                                continue;
                            case PacketCommunicatorReceiveResult.Ok:
                                {
                                    //communicator.SetFilter("ip and tcp and icmp"); //Additional information: An error has occured when compiling the filter <ip and tcp and icmp>: expression rejects all packets
                                    //Console.WriteLine(packet.Timestamp.ToString("yyyy-MM-dd hh:mm:ss.fff") + " length:" + packet.Length);
                                    ProcessIncomingPacket(packet);
                                    break;
                                }
                            default:
                                throw new InvalidOperationException("The result " + result + " shoudl never be reached here");
                        }
                    } while (true);
                }


            }
            else
            {
                return;
                //do disconnect and end of thread!
            }
        }
        private void buttonListen_Click(object sender, EventArgs e)  //server start
        {
            if (isServerListening == true) //server is already listening DO DISCONNEC
            {
                isServerListening = false;
                buttonListen.Text = "Disconnect";

                //BLBE!
                if (serverThread != null)
                {
                    //serverThread = new Thread(() => Listening(!isServerListening));
                    //serverThread.Start(); //Additional information: Odkaz na objekt není nastaven na instanci objektu.
                }

                textBoxServerStatus.Text = "disconnected";
            }
            else //server is NOT connected
            {
                isServerListening = true;
                buttonListen.Text = "Listen";

                string tmpIp;
                if (isServer)
                {
                    tmpIp = comboBoxServerAddress.SelectedValue.ToString(); //Additional information: Operace mezi vlákny není platná: Přístup k ovládacímu prvku comboBoxServerAddress proběhl z jiného vlákna než z vlákna, v rámci kterého byl vytvořen.
                }
                else
                {
                    tmpIp = comboBoxClientAddress.SelectedValue.ToString();
                }

                serverThread = new Thread(() => Listening(!isServerListening, tmpIp));
                serverThread.Start();
                textBoxServerStatus.Text = "connected";

                /*
                listener = new TcpListener(IPAddress.Parse(comboBoxServerAddress.Text), Int32.Parse(numericUpDownServerPort.Value.ToString()));
                serverThread = new Thread(() => Listening(listener));
                */
            }
        }
        private void Sending(TcpClient client)
        {
            try
            {
                NetworkStream ns = client.GetStream();
                byte[] bytes = new byte[1024];
                int bytesRead = ns.Read(bytes, 0, bytes.Length);
                Console.WriteLine(Encoding.ASCII.GetString(bytes, 0, bytesRead));
                client.Close();
            }
            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
            }

        }

        private void buttonSend_Click(object sender, EventArgs e)
        {

            /*
            try
            {
                client = new TcpClient(comboBoxClientAddress.Text, Int32.Parse(numericUpDownClientPort.Value.ToString())); //Additional information: No connection could be made because the target machine actively refused it
            }
            catch
            {
                // No connection could be made because the target machine actively refused it
                textBoxClientStatus.Text = "error";
            }

            clientThread = new Thread(() => Sending(client));
            clientThread.Start();

            textBoxClientStatus.Text = "send";
            */
        }

        private void buttonSendStop_Click(object sender, EventArgs e)
        {
            /*
            if (clientThread != null)
                clientThread.Abort();

            client = null;
            textBoxClientStatus.Text = "disconnected";
            */
        }

        private void buttonPlus_Click(object sender, EventArgs e) //one more windows agent
        {
            Form MainWindow2 = new MainWindow(!isServer); //should have constructor with iterating ports
            MainWindow2.Show();
        }

        //protection changing server/client button
        private void checkBoxServer_CheckedChanged(object sender, EventArgs e)
        {
            if (checkBoxServer.Checked)
            {
                checkBoxClient.Checked = false;
                groupBoxServer.Enabled = true;
                groupBoxMethod.Enabled = false;
                groupBoxClient.Enabled = false;
            }
            else
            {
                checkBoxClient.Checked = true;
                groupBoxServer.Enabled = false;
                groupBoxMethod.Enabled = true;
                groupBoxClient.Enabled = true;
            }
        }

        //protection changing server/client button
        private void checkBoxClient_CheckedChanged(object sender, EventArgs e)
        {
            if (checkBoxClient.Checked)
            {
                checkBoxServer.Checked = false;
                groupBoxServer.Enabled = false;
                groupBoxMethod.Enabled = true;
                groupBoxClient.Enabled = true;
            }
            else
            {
                checkBoxServer.Checked = true;
                groupBoxServer.Enabled = true;
                groupBoxMethod.Enabled = false;
                groupBoxClient.Enabled = false;
            }

        }

        private void buttonSteganogr_Click(object sender, EventArgs e)
        {
            selectedDevice = allDevices[selectedInterface(tmpIp)]; // Take the selected adapter
            //filtering https://github.com/PcapDotNet/Pcap.Net/wiki/Pcap.Net-Tutorial-Filtering-the-traffic

            if (comboBoxMethod.Text == "ICMP payload")
            {
                if (checkBoxClient.Checked) //client
                {
                    textBoxDebug.Text += "ICMP echo\r\n";
                    byte[] packetData = System.Text.ASCIIEncoding.ASCII.GetBytes(textBoxSecret.Text);
                    string ipAddress = comboBoxServerAddress.SelectedValue.ToString();
                    int portNumber = Convert.ToInt32(numericUpDownServerPort.Value);

                    //try
                    IPEndPoint otherServer = new IPEndPoint(IPAddress.Parse(ipAddress), portNumber); //An invalid IP address was specified.
                    Socket client = new Socket(System.Net.Sockets.AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Icmp); //try //Additional information: Došlo k pokusu o přístup k soketu způsobem zakázaným jeho přístupovými oprávněními
                    client.SendTo(packetData, otherServer);
                    textBoxDebug.Text += "Packet sent";
                }
                else
                {
                    //server is checked
                    textBoxDebug.Text += "Server not implemented\r\n";
                }
            }
            else if (comboBoxMethod.Text == "ICMP tunnel")
            {

            }
            else if (String.Equals(comboBoxMethod.Text, "Pokus test"))
            {
                //
            }
            else
            {
                textBoxSecret.Text = "Nothing happened";
            }
        }

        private void PacketHandler(Packet packet) // Callback function invoked by Pcap.Net for every incoming packet
        {
            textBoxDebug.Text += String.Format("{0} length: {1}", packet.Timestamp.ToString("yyyy-MM-dd hh:mm:ss.fff"), packet.Length);
        }
        private void cleanall()
        {
            /* We don't need any more the device list. Free it */
            //pcap_freealldevs(alldevs);
        }

        public void SettextBoxDebug(string text)
        {
            //this.textBoxDebug.Text += text;
            /*
                Convert to Events
                http://www.cs.vsb.cz/behalek/vyuka/pcsharp/text/ch04s11.html
                Additional information: Operace mezi vlákny není platná: Přístup k ovládacímu prvku textBoxDebug proběhl z jiného vlákna než z vlákna, v rámci kterého byl vytvořen.
            */
        }

        private int selectedInterface(string tmpIp)
        {
            //open device section
            int deviceIndex = 0, i = 0; //for device ID
            bool exit = false;

            foreach (LivePacketDevice lpd in allDevices)
            {
                if (exit)
                {
                    break;
                }

                foreach (DeviceAddress nonparsed in lpd.Addresses)
                {
                    string tmp = nonparsed.ToString();
                    string[] words = tmp.Split(' ');



                    if (String.Equals(words[2], tmpIp)) ////should be more effective by filtering IPv6
                    {
                        deviceIndex = i;
                        SettextBoxDebug(String.Format("Selected interface with {0}\r\n", words[2]));
                        exit = true;
                        break;
                    }
                    else
                    {
                        i++;
                    }
                }
            }

            if (allDevices.Count < i) //todo better!
            {
                deviceIndex = 0;
                SettextBoxDebug(String.Format("Error in selecting interface, selected first!\r\n"));
            }

            return (deviceIndex);
        }
        private void ProcessIncomingPacket(Packet packet)
        {

            //SettextBoxDebug(packet.IpV4.Identification.ToString());
            this.textBoxDebug.Text = packet.IpV4.Identification.ToString();

            /*
            IpV4Datagram ip = packet.Ethernet.IpV4;
            UdpDatagram udp = ip.Udp;
            */
        }
    }
}

