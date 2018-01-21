using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SteganoNetLib;

namespace SteganoNet.UI.Console
{
    public class InfoWriter
    {
        public volatile bool terminate = false;

        /*
        public void writeInfo(INetNode nn)
        {
            for (; ; )
            {
                System.Console.WriteLine("\t>{0}", nn.messages.Dequeue());

                if (terminate)
                {
                    return;
                }
            }
        }
        */
    }
}
