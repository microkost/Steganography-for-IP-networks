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
        private Thread clientThread;
        public NetReceiverServer listener; //for thread
        public NetSenderClient speaker; //for thread
        public delegate void writeInfoToTextBoxDelegate(INetNode nn); //delegate type 
        public writeInfoToTextBoxDelegate writeInfoToTextBox; //delegate object

        [BrowsableAttribute(false)] //debug printing
        public bool CancellationPending { get; } //debug printing

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

        /*
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
        */

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
            //textBoxDebug.Text += "----------------------------------------\r\n";

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

        private void buttonListen_Click(object sender, EventArgs e)  //LISTENING method which starting THREAD (server start)
        {
            if (isServerListening == true) //server is already listening DO DISCONNECT
            {
                isServerListening = false;
                backgroundWorkerDebugPrinter.CancelAsync(); //end backgroundworker
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
                textBoxDebug.Text += "--------------------------------------SR\r\n";
                isServerListening = true;
                buttonListen.Text = "Disconnect";
                textBoxServerStatus.Text = "connected";

                listener = new NetReceiverServer(comboBoxServerAddress.Text, (ushort)numericUpDownServerPort.Value, comboBoxClientAddress.Text, (ushort)numericUpDownClientPort.Value);                
                listener.StegoUsedMethodIds = GetSelectedMethodsIds(); //previously listener.StegoUsedMethodIds = new List<int>() { (int)listBoxMethod.SelectedValue };                

                //run server
                serverThread = new Thread(listener.Listening);
                serverThread.Start();

                //run debug output
                //writeInfoToTextBox = new writeInfoToTextBoxDelegate(WriteInfoDebug);
                //BeginInvoke(writeInfoToTextBox, listener);                
                if (backgroundWorkerDebugPrinter.IsBusy == false)
                {
                    backgroundWorkerDebugPrinter.RunWorkerAsync(listener);
                }
                else
                {
                    textBoxDebug.AppendText("output canceled due to thread utilization\r\n");
                }
            }
        }

        private void buttonSteganogr_Click(object sender, EventArgs e)
        {
            if (isClientSpeaking == true) //client is speaking DO DISCONNECT
            {
                isClientSpeaking = false;
                //backgroundWorkerDebugPrinter.CancelAsync(); //FAILING
                buttonClient.Text = "Start speaking";

                if (clientThread != null)
                {
                    speaker.Terminate = true;
                }

                textBoxClientStatus.Text = "disconnected";
            }
            else //client is NOT active
            {
                textBoxDebug.Text += "--------------------------------------CR\r\n";
                isClientSpeaking = true;
                buttonClient.Text = "Stop speaking";
                textBoxClientStatus.Text = "active";

                speaker = new NetSenderClient(comboBoxClientAddress.Text, (ushort)numericUpDownClientPort.Value, comboBoxServerAddress.Text, (ushort)numericUpDownServerPort.Value);
                speaker.SecretMessage = DataOperationsCrypto.DoCrypto(textBoxSecret.Text);
                speaker.StegoUsedMethodIds = GetSelectedMethodsIds();

                //run client
                clientThread = new Thread(speaker.Speaking);
                clientThread.Start();

                //run output
                //writeInfoToTextBox = new writeInfoToTextBoxDelegate(WriteInfoDebug); // initialize delegate object
                //BeginInvoke(writeInfoToTextBox, speaker);                                
                if (backgroundWorkerDebugPrinter.IsBusy == false)
                {
                    backgroundWorkerDebugPrinter.RunWorkerAsync(speaker);
                }
                else
                {
                    textBoxDebug.AppendText("output canceled due to thread utilization\r\n");
                }

            }
        }


        public void WriteInfoDebug(INetNode mm) //printing 
        {
            //while (!mm.AskTermination()) //console print out
            while(true)
            {
                try
                {
                    textBoxDebug.AppendText(mm.Messages.Dequeue() + "\r\n"); //show message inline on GUI                  
                }
                catch
                {
                    Thread.Sleep(1000);
                }
                //Thread.Sleep(50); //slow down output
            }
        }
        

        private void backgroundWorkerDebugPrinter_DoWork(object sender, System.ComponentModel.DoWorkEventArgs e)
        {
            INetNode mm = (INetNode)e.Argument; //parse who is debugged

            if (mm == null)
            {
                textBoxDebug.AppendText("debug output wrongly initialized\r\n");
                return;
            }

            if (this.backgroundWorkerDebugPrinter.CancellationPending) //cancelation support
            {
                e.Cancel = true;
                return;
            }

            string debufTextToAppend = "";
            while (true) //while (!mm.AskTermination()) 
            {
                try
                {
                    debufTextToAppend = mm.Messages.Dequeue().ToString();                    
                    //console print out
                    //textBoxDebug.AppendText(mm.Messages.Dequeue().ToString() + "\r\n"); //show message inline on GUI                  
                }
                catch
                {
                    //textBoxDebug.AppendText(ex.ToString()); //Message = "Cross-thread operation not valid: Control 'textBoxDebug' accessed from a thread other than the thread it was created on."
                    Thread.Sleep(1000);
                    return;
                }

                try
                {
                    SafeInvoke(textBoxDebug, () => { textBoxDebug.AppendText(debufTextToAppend + "\r\n"); });
                }
                catch
                { }

            }
        }

        public static void SafeInvoke(System.Windows.Forms.Control control, System.Action action)
        {
            if (control.InvokeRequired)
                control.Invoke(new System.Windows.Forms.MethodInvoker(() => { action(); }));
            else
                action();
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

        private void buttonPlus_Click(object sender, EventArgs e) //one more window with agent
        {
            //Form MainWindow2 = new MainWindow(!isServer, listBoxMethod.SelectedValue.ToString());
            Form MainWindow2 = new MainWindow();
            MainWindow2.Show();
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
    }
}
