﻿using System;
using System.Collections.Generic;
using SteganoNetLib;
using System.Threading;

namespace SteganoNet.UI.Console
{
    public static class ConsoleTools
    {
        public static string SelectInterface()
        {
            List<Tuple<string, string>> ipv4localadd = NetDevice.GetIPv4addressesAndDescriptionLocal();
            System.Console.WriteLine("Available interfaces as source: ");
            int interfaceCounter = 0;
            foreach (Tuple<string, string> ip in ipv4localadd)
            {
                System.Console.WriteLine(String.Format("\t{0}. {1}: {2}", interfaceCounter + 1, ip.Item1, ip.Item2));
                interfaceCounter++;
            }
            System.Console.Write("\tWhich interface do you want to use? ");
            Int32.TryParse(System.Console.ReadLine(), out interfaceCounter);

            try
            {
                return ipv4localadd[interfaceCounter - 1].Item1;
            }
            catch //System.ArgumentOutOfRangeException:
            {
                if (ipv4localadd.Count <= 0)
                    return null; //"0.0.0.0"; //TODO tricky!
                else
                    return ipv4localadd[0].Item1;
            }
        }

        public static void writeInfoConsole(object nn) //printing output from console
        {
            INetNode mm = (INetNode)(nn); //retype //TODO more than hope = try-catch
            for (;;)
            {
                try
                {
                    System.Console.WriteLine("\t>{0}", mm.messages.Dequeue());
                }
                catch
                {
                    //System.Console.WriteLine("\t>");
                    Thread.Sleep(100);
                }
            }
        }
    }
}
