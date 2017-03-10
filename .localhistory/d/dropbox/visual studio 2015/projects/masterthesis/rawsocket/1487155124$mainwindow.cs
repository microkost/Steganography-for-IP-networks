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

using PcapDotNet.Base;
using PcapDotNet.Core;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Arp;
using PcapDotNet.Packets.Dns;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.Gre;
using PcapDotNet.Packets.Http;
using PcapDotNet.Packets.Icmp;
using PcapDotNet.Packets.Igmp;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.IpV6;
using PcapDotNet.Packets.Transport;

namespace RawSocket
{
    public partial class MainWindow : Form
    {
        private Thread serverThread;
        private Thread clientThread;

        Server listener; //instantion for thread
        Client speaker;

        private bool isServer = true; //which role has app now
        private bool isServerListening = false;
        private bool isClientSpeaking = false;

        //public delegate void ParameterizedThreadStart(bool isServerListening);
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
            //AllocConsole(); //console window            

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

            if (Lib.checkPrerequisites() == false)
            {
                //get devices
                //TODO some protection
            }

            List<String> IPv4addresses = new List<String>();
            //IPv4addresses.Add("127.0.0.1"); //add localhost //DEBUG!

            int i = 0;
            foreach (LivePacketDevice lpd in Lib.allDevices)
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
                        IPv4addresses.Add(words[2]);
                        textBoxDebug.Text += String.Format("IPv4 {0}\r\n", IPv4addresses.Last());
                    }
                }
                textBoxDebug.Text += "----------------------------------------\r\n";
            }

            //IP addresses server      
            //comboBoxServerAddress.DataSource = Dns.GetHostEntry(Dns.GetHostName()).AddressList; //pure from system
            BindingSource bs_servers = new BindingSource();
            bs_servers.DataSource = IPv4addresses;
            comboBoxServerAddress.DataSource = bs_servers;
            comboBoxServerAddress.SelectedIndex = 0;

            //IP addresses client
            //comboBoxClientAddress.DataSource = Dns.GetHostEntry(Dns.GetHostName()).AddressList; //pure from system
            BindingSource bs_clients = new BindingSource();
            bs_clients.DataSource = IPv4addresses;
            comboBoxClientAddress.DataSource = bs_clients;
            comboBoxClientAddress.SelectedIndex = 0;

            //TMP TMP until combobox will be able to change and save value!
            textBoxDestination.Text = comboBoxClientAddress.SelectedValue.ToString();

            //methods combobox (text is ID for method)
            BindingSource bs_methods = new BindingSource();
            bs_methods.DataSource = Lib.listOfStegoMethods;
            comboBoxMethod.DataSource = bs_methods;
            comboBoxMethod.SelectedIndex = 0; //default method manual predefined option


        }

        //console window initialization + calling
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool AllocConsole();

        private void buttonListen_Click(object sender, EventArgs e)  //LISTENING method which starting THREAD (server start)
        {
            if (isServerListening == true) //server is already listening DO DISCONNECT
            {
                isServerListening = false;
                buttonListen.Text = "Listen";

                if (serverThread != null)
                {
                    listener.Terminate();
                }

                //pcap_freealldevs(alldevs); //We don't need any more the device list. Free it
                textBoxServerStatus.Text = "disconnected";
            }
            else //server is NOT connected
            {
                isServerListening = true;
                buttonListen.Text = "Disconnect";

                listener = new Server(this);
                listener.serverIP = comboBoxServerAddress.Text;
                listener.StegoMethod = comboBoxMethod.SelectedValue.ToString();

                serverThread = new Thread(listener.Listening);
                serverThread.Start();

                textBoxServerStatus.Text = "connected";
            }
        }
        private void buttonPlus_Click(object sender, EventArgs e) //one more window with agent
        {
            Form MainWindow2 = new MainWindow(!isServer); //should have constructor with iterating ports
            MainWindow2.Show();
        }

        private void checkBoxServer_CheckedChanged(object sender, EventArgs e) //protection changing server/client button
        {
            if (checkBoxServer.Checked)
            {
                checkBoxClient.Checked = false;
                groupBoxServer.Enabled = true;
                //groupBoxMethod.Enabled = false;
                buttonClient.Enabled = false;
                groupBoxClient.Enabled = false;
            }
            else
            {
                checkBoxClient.Checked = true;
                groupBoxServer.Enabled = false;
                //groupBoxMethod.Enabled = true;
                buttonClient.Enabled = true;
                groupBoxClient.Enabled = true;
            }
        }
        private void checkBoxClient_CheckedChanged(object sender, EventArgs e) //protection changing server/client button
        {
            if (checkBoxClient.Checked)
            {
                checkBoxServer.Checked = false;
                groupBoxServer.Enabled = false;
                //groupBoxMethod.Enabled = true;
                buttonClient.Enabled = true;
                groupBoxClient.Enabled = true;
            }
            else
            {
                checkBoxServer.Checked = true;
                groupBoxServer.Enabled = true;
                //groupBoxMethod.Enabled = false;
                buttonClient.Enabled = false;
                groupBoxClient.Enabled = false;
            }

        }
        private void buttonSteganogr_Click(object sender, EventArgs e)
        {
            if (isClientSpeaking == true) //client is speaking DO DISCONNECT
            {
                isClientSpeaking = false;
                buttonClient.Text = "Start speaking";

                if (clientThread != null)
                {
                    speaker.Terminate();
                }

                textBoxClientStatus.Text = "disconnected";
            }
            else //client is NOT active
            {
                isClientSpeaking = true;
                buttonClient.Text = "Stop speaking";

                speaker = new Client(this);
                speaker.SourceIP = comboBoxClientAddress.Text;
                speaker.DestinationIP = textBoxDestination.Text;
                speaker.StegoMethod = comboBoxMethod.SelectedValue.ToString();

                clientThread = new Thread(speaker.Speaking);
                clientThread.Start();

                textBoxClientStatus.Text = "active";
            }
        }
        private void comboBoxServerAddress_SelectedIndexChanged(object sender, EventArgs e) //autofill destination by local server IP
        {
            textBoxDestination.Text = comboBoxServerAddress.SelectedValue.ToString();
        }

        private void comboBoxMethod_SelectedIndexChanged(object sender, EventArgs e) //if you changed method, change property
        {
            if (speaker != null || listener != null)
            {
                speaker.StegoMethod = comboBoxMethod.SelectedValue.ToString();
                listener.StegoMethod = comboBoxMethod.SelectedValue.ToString();
            }

        }
    }
}
