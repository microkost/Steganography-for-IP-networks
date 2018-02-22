using System;
using System.Collections.Generic;
using System.Windows.Forms;
using System.Runtime.InteropServices; //console
using System.Threading;
using SteganoNetLib;

/***************************************************************************
 * 
 * This GUI is highly made bad, just remake of previous UI for new structure
 * 
 ***************************************************************************/
namespace SteganographyFramework
{
    public partial class MainWindow : Form
    {
        private Thread serverThread;
        private Thread clientThread;

        NetReceiverServer listener; //for thread
        NetSenderClient speaker; //for thread

        private bool isServer = true; //which role has app now
        private bool isServerListening = false;
        private bool isClientSpeaking = false;
        public MainWindow()
        {
            InitializeComponent();

            try
            {
                InitialProcedure();
            }
            catch
            {
                MessageBox.Show("Initializing of steganography application failed, please check prerequisites especially availability of WinPcap, ", "Run problem", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            try
            {
                comboBoxMethod.SelectedIndex = 0; //debug developer settings
            }
            catch
            {
            }
        }

        public MainWindow(bool isServer, string method)
        {
            InitializeComponent();
            this.isServer = isServer; //isServer == false then isClient
            InitialProcedure();
            try
            {
                comboBoxMethod.SelectedIndex = comboBoxMethod.FindStringExact(method);
            }
            catch
            {
            }
        }

        private void InitialProcedure()
        {
            //AllocConsole(); //console window for debug in classes

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

            if (SteganoNet.Lib.SystemCheck.AreSystemPrerequisitiesDone() == false)
            {
                throw new Exception("Initializing of steganography application failed, please check prerequisites especially availability of WinPcap");
            }

            List<String> IPv4addresses = NetDevice.GetIPv4addressesLocal();
            //IPv4addresses.Add("127.0.0.1"); //add localhost //TODO                       

            foreach (string ipa in IPv4addresses) //print out
            {
                textBoxDebug.Text += String.Format("IPv4 {0}\r\n", ipa);
            }
            textBoxDebug.Text += "----------------------------------------\r\n";


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
            //BindingSource bs_methods = new BindingSource();
            //bs_methods.DataSource = Lib.listOfStegoMethods;
            //comboBoxMethod.DataSource = bs_methods;

            Dictionary<int, string> allmethods = NetSteganography.GetListStegoMethodsIdAndKey();
            comboBoxMethod.DataSource = new BindingSource(allmethods, null);
            comboBoxMethod.DisplayMember = "Value";
            comboBoxMethod.ValueMember = "Key";
            comboBoxMethod.SelectedIndex = 0; //default method manual predefined option
        }

        //console window initialization + calling
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool AllocConsole();

        private void buttonListen_Click(object sender, EventArgs e)  //LISTENING method which starting THREAD (server start)
        {
            //TODO add thread joining!

            if (isServerListening == true) //server is already listening DO DISCONNECT
            {
                isServerListening = false;
                buttonListen.Text = "Listen";

                if (serverThread != null)
                {
                    listener.Terminate = true;
                }

                //pcap_freealldevs(alldevs); //We don't need any more the device list. Free it
                textBoxServerStatus.Text = "disconnected";
            }
            else //server is NOT connected
            {
                isServerListening = true;
                buttonListen.Text = "Disconnect";

                //listener = new Server(this);
                //listener.serverIP = new IpV4Address(comboBoxServerAddress.Text);
                //listener.StegoMethod = comboBoxMethod.SelectedValue.ToString();
                //listener.DestinationPort = (ushort)numericUpDownServerPort.Value;

                listener = new NetReceiverServer(comboBoxServerAddress.Text, (ushort)numericUpDownServerPort.Value, comboBoxClientAddress.Text, (ushort)numericUpDownClientPort.Value);
                listener.StegoUsedMethodIds = new List<int>() { (int)comboBoxMethod.SelectedValue };

                serverThread = new Thread(listener.Listening);
                serverThread.Start();

                textBoxServerStatus.Text = "connected";

                /*
                //needs to be in separate thread... Kills UI otherwise
                while (listener.Terminate == false) //console print out
                {
                    try
                    {
                        textBoxDebug.Text += listener.Messages.Dequeue(); //show lastest message                   
                    }
                    catch
                    {
                        System.Threading.Thread.Sleep(100);
                    }
                }
                */
            }
        }
        private void buttonPlus_Click(object sender, EventArgs e) //one more window with agent
        {
            Form MainWindow2 = new MainWindow(!isServer, comboBoxMethod.SelectedValue.ToString());
            MainWindow2.Show();
        }

        private void checkBoxServer_CheckedChanged(object sender, EventArgs e) //protection changing server/client button
        {
            if (checkBoxServer.Checked)
            {
                checkBoxClient.Checked = false;
                groupBoxServer.Enabled = true;
                //groupBoxMethod.Enabled = false;
                textBoxSecret.Enabled = false;
                buttonClient.Enabled = false;
                groupBoxClient.Enabled = false;
            }
            else
            {
                checkBoxClient.Checked = true;
                groupBoxServer.Enabled = false;
                //groupBoxMethod.Enabled = true;
                textBoxSecret.Enabled = true;
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
                textBoxSecret.Enabled = true;
                buttonClient.Enabled = true;
                groupBoxClient.Enabled = true;
            }
            else
            {
                checkBoxServer.Checked = true;
                groupBoxServer.Enabled = true;
                //groupBoxMethod.Enabled = false;
                textBoxSecret.Enabled = false;
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
                    speaker.Terminate = true;
                }

                textBoxClientStatus.Text = "disconnected";
            }
            else //client is NOT active
            {
                isClientSpeaking = true;
                buttonClient.Text = "Stop speaking";

                //speaker = new Client(this);
                //speaker.SourceIP = new IpV4Address(comboBoxClientAddress.Text);
                //speaker.DestinationIP = new IpV4Address(textBoxDestination.Text);
                //speaker.StegoMethod = comboBoxMethod.SelectedValue.ToString();
                //speaker.DestinationPort = Convert.ToUInt16(numericUpDownServerPort.Value);
                //speaker.SourcePort = Convert.ToUInt16(numericUpDownClientPort.Value); //should be (ushort)(4123 + new Random().Next() % 1000);
                //speaker.Secret = textBoxSecret.Text;

                speaker = new NetSenderClient(comboBoxClientAddress.Text, (ushort)numericUpDownClientPort.Value, comboBoxServerAddress.Text, (ushort)numericUpDownServerPort.Value);
                speaker.SecretMessage = DataOperationsCrypto.DoCrypto(textBoxSecret.Text);
                speaker.StegoUsedMethodIds = new List<int>() { (int)comboBoxMethod.SelectedValue };

                clientThread = new Thread(speaker.Speaking);
                clientThread.Start();

                textBoxClientStatus.Text = "active";

                /* 
                //needs to be in separate thread... Kills UI otherwise
                while (speaker.Terminate == false) //console print out
                {
                    try
                    {
                        textBoxDebug.Text += speaker.Messages.Dequeue(); //show lastest message                   
                    }
                    catch
                    {
                        System.Threading.Thread.Sleep(100);
                    }
                }
                */
            }
        }
        private void comboBoxServerAddress_SelectedIndexChanged(object sender, EventArgs e) //autofill destination by local server IP
        {
            textBoxDestination.Text = comboBoxServerAddress.SelectedValue.ToString();
        }

        private void comboBoxMethod_SelectedIndexChanged(object sender, EventArgs e) //if you changed method, change property!
        {
            if (speaker != null)
            {
                //speaker.StegoMethod = comboBoxMethod.SelectedValue.ToString();
                speaker.StegoUsedMethodIds = new List<int>() { (int)comboBoxMethod.SelectedValue };
            }

            if (listener != null)
            {
                //listener.StegoMethod = comboBoxMethod.SelectedValue.ToString();
                listener.StegoUsedMethodIds = new List<int>() { (int)comboBoxMethod.SelectedValue };
            }

        }
    }
}
