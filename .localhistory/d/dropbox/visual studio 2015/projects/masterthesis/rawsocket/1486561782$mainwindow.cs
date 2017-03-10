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

namespace RawSocket
{
    public partial class MainWindow : Form
    {
        private TcpListener listener;
        private Thread serverThread;

        private TcpClient client;
        private Thread clientThread;

        private bool isServer = true;

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
            AllocConsole(); //console window

            //IP address 
            comboBoxServerAddress.DataSource = Dns.GetHostEntry(Dns.GetHostName()).AddressList;
            comboBoxServerAddress.SelectedIndex = 8; //hardcoded!

            comboBoxClientAddress.DataSource = Dns.GetHostEntry(Dns.GetHostName()).AddressList;
            comboBoxClientAddress.SelectedIndex = 8;

            comboBoxMethod.SelectedIndex = 0;
        }

        //console window initialization
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool AllocConsole();

        private static void Listening(TcpListener listener)
        {
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
        }
        private void buttonListen_Click(object sender, EventArgs e)  //server start
        {
            listener = new TcpListener(IPAddress.Parse(comboBoxServerAddress.Text), Int32.Parse(numericUpDownServerPort.Value.ToString()));

            serverThread = new Thread(() => Listening(listener));
            serverThread.Start();

            textBoxServerStatus.Text = "connected";
        }


        private void ListenStop_Click(object sender, EventArgs e) //server stop
        {
            if (serverThread != null)
                serverThread.Abort(); //doesnt work

            listener = null;
            textBoxServerStatus.Text = "disconnected";
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
        }
        private void buttonSendStop_Click(object sender, EventArgs e)
        {
            if (clientThread != null)
                clientThread.Abort();

            client = null;
            textBoxClientStatus.Text = "disconnected";
        }

        private void buttonPlus_Click(object sender, EventArgs e) //one more windows agent
        {
            Form MainWindow2 = new MainWindow(!isServer); //should have constructor with iterating ports
            MainWindow2.Show();

        }

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
            switch (comboBoxMethod.SelectedIndex)
            {
                default:
                    { textBoxSecret.Text = "Nothing"; break; }
                case ('0'): //FTP
                    {

                      break;
                    }
            }

        }
    }
}
