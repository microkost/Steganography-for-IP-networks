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
        Server listener;
        Client speaker;

        private bool isServer = true;
        private bool isServerListening = false;







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

            //get devices

            // TODO pred listening/connect
            //if (allDevices.Count == 0)
            //    textBoxDebug.Text += "No interfaces found! Make sure WinPcap is installed.\n";

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
            textBoxTmpIp.Text = comboBoxClientAddress.SelectedValue.ToString();

            //methods combobox (text is ID for method)
            List<String> methods = new List<String>();
            methods.Add("ICMP payload");
            methods.Add("IPv4 manipulation");
            methods.Add("TCP manipulation");
            BindingSource bs_methods = new BindingSource();
            bs_methods.DataSource = methods;
            comboBoxMethod.DataSource = bs_methods;
            comboBoxMethod.SelectedIndex = 2; //default method manual predefined option


        }

        //console window initialization
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
                listener.tmpIp = comboBoxServerAddress.Text;

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
                buttonSteganogr.Enabled = false;
                groupBoxClient.Enabled = false;
            }
            else
            {
                checkBoxClient.Checked = true;
                groupBoxServer.Enabled = false;
                //groupBoxMethod.Enabled = true;
                buttonSteganogr.Enabled = true;
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
                buttonSteganogr.Enabled = true;
                groupBoxClient.Enabled = true;
            }
            else
            {
                checkBoxServer.Checked = true;
                groupBoxServer.Enabled = true;
                //groupBoxMethod.Enabled = false;
                buttonSteganogr.Enabled = false;
                groupBoxClient.Enabled = false;
            }

        }
        private void buttonSteganogr_Click(object sender, EventArgs e)
        {


        }






        //service methods:
        private void PacketHandler(Packet packet) // Callback function invoked by Pcap.Net for every incoming packet
        {
            textBoxDebug.Text += String.Format("{0} length: {1}", packet.Timestamp.ToString("yyyy-MM-dd hh:mm:ss.fff"), packet.Length);
        }





        private string GetSeletedIP(bool isServer) //returns string with IP address of server or client
        {
            //missing protection of inicialization

            string selectedInterfaceIPaddress = "";
            //ComboBox combac = comboBoxServerAddress;
            if (isServer)
            {
                //PRO ZAPIS
                /*this.Invoke((MethodInvoker)delegate {
                    comboBoxServerAddress.Text = "1"; // runs on UI thread
                });
                */
                selectedInterfaceIPaddress = comboBoxServerAddress.SelectedValue.ToString();
            }
            else
            {
                selectedInterfaceIPaddress = comboBoxClientAddress.SelectedValue.ToString(); //Additional information: Cross-thread operation not valid: Control 'comboBoxClientAddress' accessed from a thread other than the thread it was created on.
            }
            return selectedInterfaceIPaddress;
        }
    }
}
