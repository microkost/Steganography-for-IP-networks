﻿using System;
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
        private Thread clientThread;

        private bool isServer = true;
        private bool isServerListening = false;

        public IList<LivePacketDevice> allDevices; //list of network interfaces
        PacketDevice selectedDevice = null; //which device will be used for communication

        public delegate void ParameterizedThreadStart(TcpListener listener);
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
            //AllocConsole(); //console window

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
        //[DllImport("kernel32.dll", SetLastError = true)]
        //[return: MarshalAs(UnmanagedType.Bool)]
        //static extern bool AllocConsole();

        private void Listening()
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

                    string tmpIp;
                    if (isServer)
                    {
                        tmpIp = comboBoxServerAddress.SelectedValue.ToString();
                    }
                    else
                    {
                        tmpIp = comboBoxClientAddress.SelectedValue.ToString();
                    }

                    if (String.Equals(words[2], tmpIp)) ////should be more effective by filtering IPv6
                    {
                        deviceIndex = i;
                        textBoxDebug.Text += String.Format("Selected interface with {0}\r\n", words[2]);
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
                textBoxDebug.Text += String.Format("Error in selecting interface, selected first!\r\n");
            }

            selectedDevice = allDevices[deviceIndex]; // Take the selected adapter

            // Open the device
            // portion of the packet to capture
            // 65536 guarantees that the whole packet will be captured on all the link layers
            // promiscuous mode
            // read timeout
            using (PacketCommunicator communicator = selectedDevice.Open(65536, PacketDeviceOpenAttributes.Promiscuous, 1000))
            {
                //https://github.com/PcapDotNet/Pcap.Net/wiki/Pcap.Net-Tutorial-Opening-an-adapter-and-capturing-the-packets
                textBoxDebug.Text += String.Format("Listening on {0}...", selectedDevice.Description);

                // start the capture
                communicator.ReceivePackets(0, PacketHandler);
            }


            /*
            bool done = false;
            listener.Start(); //System.Net.Sockets.SocketException An attempt was made to access a socket in a way forbidden by its access permissions
                              //Only one usage of each socket address (protocol/network address/port) is normally permitted

            while (!done)
            {
                Console.WriteLine("Waiting for connection...");
                TcpClient client = listener.AcceptTcpClient();

                Console.WriteLine("Connection accepted.");

                NetworkStream ns = client.GetStream();
                byte[] byteTime = Encoding.ASCII.GetBytes(DateTime.Now.ToString());

                try
                {
                    ns.Write(byteTime, 0, byteTime.Length);
                    ns.Close();
                    client.Close();
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.ToString());
                }

                listener.Stop();
                done = true;
                Console.WriteLine("Disconnected.");
            }
            */
        }
        private void buttonListen_Click(object sender, EventArgs e)  //server start
        {
            if (isServerListening == true) //server is already listening do disconnect
            {
                isServerListening = false;
                buttonListen.Text = "Disconnect";

                /*
                listener = new TcpListener(IPAddress.Parse(comboBoxServerAddress.Text), Int32.Parse(numericUpDownServerPort.Value.ToString()));
                serverThread = new Thread(() => Listening(listener));
                */

                serverThread = new Thread(() => Listening(!isServerListening));
                serverThread.Start();

                textBoxServerStatus.Text = "disconnected";
            }
            else //server is NOT connected
            {
                isServerListening = true;
                buttonListen.Text = "Listen";
                
                if (serverThread != null)
                    serverThread = new Thread(() => Listening(!isServerListening));
                    serverThread.Start(); //co tady s tímto?

                textBoxServerStatus.Text = "connected";
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
                groupBoxClient.Enabled = false;
            }
            else
            {
                checkBoxClient.Checked = true;
                groupBoxServer.Enabled = false;
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
                groupBoxClient.Enabled = true;
            }
            else
            {
                checkBoxServer.Checked = true;
                groupBoxServer.Enabled = true;
                groupBoxClient.Enabled = false;
            }

        }

        private void buttonSteganogr_Click(object sender, EventArgs e)
        {           

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
    }
}

