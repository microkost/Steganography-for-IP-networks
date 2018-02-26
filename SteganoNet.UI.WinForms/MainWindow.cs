using System;
using System.Collections.Generic;
using System.Windows.Forms;
//using System.Runtime.InteropServices; //console
using System.Threading;
using SteganoNetLib;
using System.Data;
using System.Linq;
using System.ComponentModel;

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
        public NetReceiverServer listener; //for serverThread
        private Thread clientThread;
        public NetSenderClient speaker; //for clientThread
        delegate void AppendDebugCallback(string text); //debug output delegate
               
        private bool isServer = true; //which role has app now
        private bool isServerListening = false;        
        private bool isClientSpeaking = false;
        private bool closeDebug = false; //debug output delegate async closer

        public MainWindow() //ctor default generic
        {
            if (SteganoNet.Lib.SystemCheck.AreSystemPrerequisitiesDone() == false)
            {
                throw new Exception("Initializing of steganography application failed, please check prerequisites especially availability of WinPcap");
            }

            InitializeComponent(); //gui
            InitialProcedure(); //correct settings of gui

            /*
            try
            {
                listBoxMethod.SelectedIndex = 0; //debug developer settings
            }
            catch { }
            */
        }

        public MainWindow(bool isServer, string method) //ctor with role specified
        {
            if (SteganoNet.Lib.SystemCheck.AreSystemPrerequisitiesDone() == false)
            {
                throw new Exception("Initializing of steganography application failed, please check prerequisites especially availability of WinPcap");
            }

            this.isServer = isServer; //isServer == false then isClient

            InitializeComponent(); //gui
            InitialProcedure(); //correct settings of gui

            /*
            try
            {
                listBoxMethod.SelectedIndex = listBoxMethod.FindStringExact(method);
            }
            catch{}            
            */
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

            List<String> IPv4addresses = NetDevice.GetIPv4addressesLocal();
            foreach (string ipa in IPv4addresses) //print out
            {
                textBoxDebug.AppendText(String.Format("Available IPv4: {0}\r\n", ipa));
            }

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
            
            backgroundWorkerDebugPrinter.WorkerSupportsCancellation = true; //cancel txt output debuging
        }

        private void ButtonListen_Click(object sender, EventArgs e)  //LISTENING method which starting THREAD (server start)
        {
            if (isServerListening == true) //server is already listening DO DISCONNECT
            {
                if (serverThread != null)
                {
                    listener.Terminate = true;
                }
                
                if (backgroundWorkerDebugPrinter.IsBusy) //END backgroundWorkerDebugPrinter
                {
                    closeDebug = true;
                    backgroundWorkerDebugPrinter.CancelAsync();
                }

                isServerListening = false;
                buttonListen.Text = "Listen";                
                textBoxServerStatus.Text = "disconnected";
                //pcap_freealldevs(alldevs); //We don't need any more the device list. Free it
            }
            else //server is NOT connected
            {
                textBoxDebug.Text += "----------------------------------------------------------------------------SR\r\n";
                isServerListening = true;
                closeDebug = false;
                buttonListen.Text = "Disconnect";
                textBoxServerStatus.Text = "connected";

                listener = new NetReceiverServer(comboBoxServerAddress.Text, (ushort)numericUpDownServerPort.Value, comboBoxClientAddress.Text, (ushort)numericUpDownClientPort.Value);
                listener.StegoUsedMethodIds = GetSelectedMethodsIds(); //previously listener.StegoUsedMethodIds = new List<int>() { (int)listBoxMethod.SelectedValue };                

                //run server
                serverThread = new Thread(listener.Listening);
                serverThread.Start();

                //run debug output
                if (backgroundWorkerDebugPrinter.IsBusy == false)
                {
                    backgroundWorkerDebugPrinter.RunWorkerAsync(listener);
                }
                else
                {
                    textBoxDebug.AppendText("Output canceled due to thread utilization\r\n");
                }
            }
        }

        private void ButtonSteganogr_Click(object sender, EventArgs e)
        {
            if (isClientSpeaking == true) //client is speaking DO DISCONNECT
            {
                if (clientThread != null)
                {
                    speaker.Terminate = true;
                }

                if (backgroundWorkerDebugPrinter.IsBusy) //END backgroundWorkerDebugPrinter
                {
                    closeDebug = true;
                    backgroundWorkerDebugPrinter.CancelAsync();
                }

                isClientSpeaking = false;
                buttonClient.Text = "Start speaking";             
                textBoxClientStatus.Text = "disconnected";
            }
            else //client is NOT active
            {
                textBoxDebug.Text += "----------------------------------------------------------------------------CR\r\n";
                isClientSpeaking = true;
                closeDebug = false;
                buttonClient.Text = "Stop speaking";
                textBoxClientStatus.Text = "active";

                speaker = new NetSenderClient(comboBoxClientAddress.Text, (ushort)numericUpDownClientPort.Value, comboBoxServerAddress.Text, (ushort)numericUpDownServerPort.Value);
                speaker.SecretMessage = DataOperationsCrypto.DoCrypto(textBoxSecret.Text);
                speaker.StegoUsedMethodIds = GetSelectedMethodsIds();

                //run client
                clientThread = new Thread(speaker.Speaking);
                clientThread.Start();

                //run output
                if (backgroundWorkerDebugPrinter.IsBusy == false)
                {
                    backgroundWorkerDebugPrinter.RunWorkerAsync(speaker);
                }
                else
                {
                    textBoxDebug.AppendText("Output canceled due to thread utilization\r\n");
                }
            }
        }

        private void BackgroundWorkerDebugPrinter_DoWork(object sender, System.ComponentModel.DoWorkEventArgs e) //runs silently and checking debug messages
        {
            INetNode mm = (INetNode)e.Argument; //parse what is debugged
            if (mm == null)
            {
                return;
            }
                        
            while (true)
            {
                if (closeDebug == true)
                {
                    AppendDebugText("Output suspended" + "\r\n");
                    break;
                }

                try
                {
                    //textBoxDebug.AppendText(mm.Messages.Dequeue() + "\r\n"); //unsafe
                    AppendDebugText(mm.Messages.Dequeue().ToString() + "\r\n"); //safely show message inline on GUI           
                }
                catch
                {
                    Thread.Sleep(1000);
                }

                //Thread.Sleep(100); //slow down output
            }
        }

        private void AppendDebugText(string text) //safe appending to textBoxDebug support method
        {
            // InvokeRequired required compares the thread ID of the calling thread to the thread ID of the creating thread.
            if (this.textBoxDebug.InvokeRequired) //If these threads are different, it returns true.
            {
                AppendDebugCallback adc = new AppendDebugCallback(AppendDebugText);
                this.Invoke(adc, new object[] { text });
            }
            else
            {
                this.textBoxDebug.AppendText(text);
            }
        }

        private List<int> GetSelectedMethodsIds() //parsing methods ids from ListBox
        {
            List<int> selectedIDs = new List<int>();
            foreach (int i in listBoxMethod.SelectedIndices)
            {
                KeyValuePair<int, string> item = (KeyValuePair<int, string>)listBoxMethod.Items[i]; //TODO protection
                selectedIDs.Add(item.Key);
            }
            textBoxDebug.AppendText("Selected methods IDs: " + string.Join(", ", selectedIDs) + "\r\n");
            return selectedIDs;
        }

        private void ButtonPlus_Click(object sender, EventArgs e) //one more window with agent
        {
            Form MainWindow2 = new MainWindow(!isServer, listBoxMethod.SelectedValue.ToString());
            //Form MainWindow2 = new MainWindow();
            MainWindow2.Show();
        }

        private void ComboBoxServerAddress_SelectedIndexChanged(object sender, EventArgs e) //autofill destination by local server IP
        {
            textBoxDestination.Text = comboBoxServerAddress.SelectedValue.ToString();
        }

        private void ComboBoxMethod_SelectedIndexChanged(object sender, EventArgs e) //if you changed method, change property
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

        private void CheckBoxServer_CheckedChanged(object sender, EventArgs e) //protection changing server/client button
        {
            if (checkBoxServer.Checked)
            {
                checkBoxClient.Checked = false;
                groupBoxServer.Enabled = true;
                textBoxSecret.Enabled = false;
                buttonClient.Enabled = false;
                groupBoxClient.Enabled = false;
                //groupBoxMethod.Enabled = false;
            }
            else
            {
                checkBoxClient.Checked = true;
                groupBoxServer.Enabled = false;
                textBoxSecret.Enabled = true;
                buttonClient.Enabled = true;
                groupBoxClient.Enabled = true;
                //groupBoxMethod.Enabled = true;
            }
        }
        private void CheckBoxClient_CheckedChanged(object sender, EventArgs e) //protection changing server/client button
        {
            if (checkBoxClient.Checked)
            {
                checkBoxServer.Checked = false;
                groupBoxServer.Enabled = false;
                textBoxSecret.Enabled = true;
                buttonClient.Enabled = true;
                groupBoxClient.Enabled = true;
                //groupBoxMethod.Enabled = true;
            }
            else
            {
                checkBoxServer.Checked = true;
                groupBoxServer.Enabled = true;
                textBoxSecret.Enabled = false;
                buttonClient.Enabled = false;
                groupBoxClient.Enabled = false;
                //groupBoxMethod.Enabled = false;
            }
        }
    }
}

