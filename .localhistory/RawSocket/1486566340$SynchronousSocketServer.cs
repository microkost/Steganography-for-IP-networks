using System;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace RawSocket
{
    //https://msdn.microsoft.com/en-us/library/6y0e13d3(v=vs.110).aspx
    public class SynchronousSocketListener
    {
        // Incoming data from the client.
        public static string data = null;

        Socket listener;

        // Data buffer for incoming data.
        byte[] bytes = new Byte[1024];

        public string StartListening()
        {
                      
            // Establish the local endpoint for the socket.
            // Dns.GetHostName returns the name of the 
            // host running the application.
            IPHostEntry ipHostInfo = Dns.GetHostEntry(Dns.GetHostName());
            IPAddress ipAddress = ipHostInfo.AddressList[3];                    //hardcoded!
            IPEndPoint localEndPoint = new IPEndPoint(ipAddress, 11000);

            // Create a TCP/IP socket.
            listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

            // Bind the socket to the local endpoint and 
            // listen for incoming connections.
            try
            {
                listener.Bind(localEndPoint);
                listener.Listen(10);
            }
            catch (Exception e)
            {
                return(e.ToString());
            }

            return (listener.ToString());
        }

        public string Listen()
        {
            if (listener == null)
                StartListening(); //WARNING

            // Start listening for connections.
            while (true)
            {
                Console.WriteLine("Waiting for a connection...");
                // Program is suspended while waiting for an incoming connection.
                Socket handler = listener.Accept();
                data = null;

                // An incoming connection needs to be processed.
                while (true)
                {
                    bytes = new byte[1024];
                    int bytesRec = handler.Receive(bytes);
                    data += Encoding.ASCII.GetString(bytes, 0, bytesRec);
                    if (data.IndexOf("<EOF>") > -1)
                    {
                        break;
                    }
                }

                // Show the data on the console.
                Console.WriteLine("Text received : {0}", data);

                // Echo the data back to the client.
                byte[] msg = Encoding.ASCII.GetBytes(data);

                handler.Send(msg);
                handler.Shutdown(SocketShutdown.Both);
                handler.Close();
            }            
        }       
    }


}