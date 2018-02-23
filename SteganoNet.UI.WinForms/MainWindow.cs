using System;
using System.Collections.Generic;
using System.Windows.Forms;
//using System.Runtime.InteropServices; //console
using System.Threading;
using SteganoNetLib;
using System.Data;
using System.Linq;

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
        public NetReceiverServer listener; //for thread
        public NetSenderClient speaker; //for thread
        public delegate void writeInfoToTextBoxDelegate(INetNode nn); //delegate type 
        public writeInfoToTextBoxDelegate writeInfoToTextBox; //delegate object

        private bool isServer = true; //which role has app now
        private bool isServerListening = false;
        private bool isClientSpeaking = false;

        public MainWindow()
        {
            if (SteganoNet.Lib.SystemCheck.AreSystemPrerequisitiesDone() == false)
            {
                throw new Exception("Initializing of steganography application failed, please check prerequisites especially availability of WinPcap");
            }

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
                listBoxMethod.SelectedIndex = 0; //debug developer settings
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
                listBoxMethod.SelectedIndex = listBoxMethod.FindStringExact(method);
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

            List<String> IPv4addresses = NetDevice.GetIPv4addressesLocal();

            foreach (string ipa in IPv4addresses) //print out
            {
                textBoxDebug.AppendText(String.Format("Available IPv4: {0}\r\n", ipa));
            }
            textBoxDebug.Text += "----------------------------------------\r\n";

            //IP addresses server      
            //comboBoxServerAddress.DataSource = Dns.GetHostEntry(Dns.GetHostName()).AddressList; //pure from system
            BindingSource bs_servers = new BindingSource();
            bs_servers.DataSource = IPv4addresses;
            comboBoxServerAddress.DataSource = bs_servers;
            comboBoxServerAddress.SelectedIndex = bs_servers.Count - 1; //try-catch

            //IP addresses client
            //comboBoxClientAddress.DataSource = Dns.GetHostEntry(Dns.GetHostName()).AddressList; //pure from system
            BindingSource bs_clients = new BindingSource();
            bs_clients.DataSource = IPv4addresses;
            comboBoxClientAddress.DataSource = bs_clients;
            comboBoxClientAddress.SelectedIndex = bs_clients.Count - 1; //try-catch

            //TMP until combobox will be able to change and save value
            textBoxDestination.Text = comboBoxClientAddress.SelectedValue.ToString();

            Dictionary<int, string> allmethods = NetSteganography.GetListStegoMethodsIdAndKey();
            listBoxMethod.DataSource = new BindingSource(allmethods, null);
            listBoxMethod.DisplayMember = "Value";
            listBoxMethod.ValueMember = "Key";
            listBoxMethod.SelectedIndex = 0; //default method manual predefined option
        }

        //console window initialization + calling
        //[DllImport("kernel32.dll", SetLastError = true)]
        //[return: MarshalAs(UnmanagedType.Bool)]
        //static extern bool AllocConsole();

        private void buttonListen_Click(object sender, EventArgs e)  //LISTENING method which starting THREAD (server start)
        {
            //TODO add thread joining!

            if (isServerListening == true) //server is already listening DO DISCONNECT
            {
                isServerListening = false;
                //end delegate
                buttonListen.Text = "Listen";
                textBoxDebug.Text += "----------------------------------------\r\n";

                if (serverThread != null)
                {
                    listener.Terminate = true;
                }

                //pcap_freealldevs(alldevs); //We don't need any more the device list. Free it
                textBoxServerStatus.Text = "disconnected";
                textBoxDebug.Text += "----------------------------------------\r\n";
            }
            else //server is NOT connected
            {
                isServerListening = true;
                buttonListen.Text = "Disconnect";

                listener = new NetReceiverServer(comboBoxServerAddress.Text, (ushort)numericUpDownServerPort.Value, comboBoxClientAddress.Text, (ushort)numericUpDownClientPort.Value);
                //listener.StegoUsedMethodIds = new List<int>() { (int)listBoxMethod.SelectedValue };                
                listener.StegoUsedMethodIds = GetSelectedMethodsIds();

                serverThread = new Thread(listener.Listening);
                serverThread.Start();

                textBoxServerStatus.Text = "connected";

                writeInfoToTextBox = new writeInfoToTextBoxDelegate(WriteInfoDebug);
                Invoke(writeInfoToTextBox, listener);
            }
        }

        private List<int> GetSelectedMethodsIds()
        {
            List<int> selectedIDs = new List<int>();
            foreach (int i in listBoxMethod.SelectedIndices)
            {
                KeyValuePair<int, string> item = (KeyValuePair<int, string>)listBoxMethod.Items[i]; //TODO protection
                selectedIDs.Add(item.Key);
            }
            textBoxDebug.AppendText(string.Join(", ", selectedIDs) + "\r\n");
            return selectedIDs;
        }

        private void buttonPlus_Click(object sender, EventArgs e) //one more window with agent
        {
            Form MainWindow2 = new MainWindow(!isServer, listBoxMethod.SelectedValue.ToString());
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
                //printClientDebug.Abort();
                //updateTextBox.EndInvoke();
                buttonClient.Text = "Start speaking";
                textBoxDebug.Text += "----------------------------------------\r\n";

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
                textBoxDebug.Text += "----------------------------------------\r\n";

                //speaker = new Client(this);
                //speaker.SourceIP = new IpV4Address(comboBoxClientAddress.Text);
                //speaker.DestinationIP = new IpV4Address(textBoxDestination.Text);
                //speaker.StegoMethod = comboBoxMethod.SelectedValue.ToString();
                //speaker.DestinationPort = Convert.ToUInt16(numericUpDownServerPort.Value);
                //speaker.SourcePort = Convert.ToUInt16(numericUpDownClientPort.Value); //should be (ushort)(4123 + new Random().Next() % 1000);
                //speaker.Secret = textBoxSecret.Text;

                speaker = new NetSenderClient(comboBoxClientAddress.Text, (ushort)numericUpDownClientPort.Value, comboBoxServerAddress.Text, (ushort)numericUpDownServerPort.Value);
                speaker.SecretMessage = DataOperationsCrypto.DoCrypto(textBoxSecret.Text);

                //speaker.StegoUsedMethodIds = new List<int>() { (int)listBoxMethod.SelectedValue };                
                speaker.StegoUsedMethodIds = GetSelectedMethodsIds();

                clientThread = new Thread(speaker.Speaking);
                clientThread.Start();

                textBoxClientStatus.Text = "active";

                writeInfoToTextBox = new writeInfoToTextBoxDelegate(WriteInfoDebug); // initialize delegate object
                Invoke(writeInfoToTextBox, speaker);
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
                List<int> selectedIDs = new List<int>();
                foreach (int element in listBoxMethod.SelectedIndices)
                {
                    selectedIDs.Add((int)element);
                }
                textBoxDebug.AppendText(selectedIDs.ToArray().ToString());
                speaker.StegoUsedMethodIds = selectedIDs;
            }

            if (listener != null)
            {
                //listener.StegoMethod = comboBoxMethod.SelectedValue.ToString();
                //listener.StegoUsedMethodIds = new List<int>() { (int)listBoxMethod.SelectedValue };                
                listener.StegoUsedMethodIds = GetSelectedMethodsIds();
            }
        }

        public void WriteInfoDebug(INetNode mm) //printing 
        {
            while (!mm.AskTermination()) //console print out
            {
                try
                {
                    textBoxDebug.AppendText(mm.Messages.Dequeue() + "\r\n"); //show message inline on GUI                  
                }
                catch
                {
                    Thread.Sleep(100);
                }
            }
        }
    }
}
