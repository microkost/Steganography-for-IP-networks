using System;
using PcapDotNet.Core;
using System.Collections.Generic;
using SteganoNetLib;
using System.Threading;
using System.Linq;

namespace SteganoNet.UI.Console
{
    public static class ConsoleTools
    {
        public static string SelectInterface()
        {
            List<Tuple<string, string>> ipv4localadd;
            try
            {
                ipv4localadd = NetDevice.GetIPv4addressesAndDescriptionLocal();
            }
            catch //System.TypeInitializationException
            {                
                System.Console.WriteLine("\tError! Library PcapDotNet.Core.dll is missing dependencies (msvcr100.dll + msvcp100.dll).\n\tOr you are running this app on VIRTUAL machine where is NOT supported.");
                return null;
            }

            System.Console.WriteLine("\tAvailable interfaces as source: ");
            int interfaceCounter = 0;
            foreach (Tuple<string, string> ip in ipv4localadd)
            {
                System.Console.WriteLine(String.Format("\t\t{0}. {1}: {2}", interfaceCounter + 1, ip.Item1, ip.Item2));
                interfaceCounter++;
            }
            System.Console.Write("\t\tWhich interface number do you want to use? ");
            Int32.TryParse(System.Console.ReadLine(), out interfaceCounter);

            try
            {
                return ipv4localadd[interfaceCounter - 1].Item1;
            }
            catch //System.ArgumentOutOfRangeException:
            {
                System.Console.WriteLine("No interface found in this computer! Cannot continue...");

                if (ipv4localadd.Count <= 0)
                    return null;
                else
                    return ipv4localadd[0].Item1;                
            }
        }

        public static void WriteInfoConsole(object nn) //printing output from console
        {
            INetNode mm = (INetNode)(nn); //it's OK?           
            try
            {
                System.Console.WriteLine("\t>{0}", mm.Messages.Dequeue());
            }
            catch
            {
                Thread.Sleep(100);
            }
        }

        internal static List<int> SelectStegoMethods() //console selection menu
        {
            Dictionary<int, string> allmethods = NetSteganography.GetListStegoMethodsIdAndKey();
            List<int> selectedMethodsID = new List<int>();
            System.Console.WriteLine("\tSelect suitable steganoghraphy methods: ");

            for (int i = 0; i < allmethods.Count; i++) //method printer
            {
                var item = allmethods.ElementAt(i);
                System.Console.WriteLine(String.Format("\t\t{0}.  {1} (id: {2})", i + 1, item.Value, item.Key));
            }
            System.Console.Write("\tEnter numbers of methods separated by comma (1,2): ");
            string selectionIndexes = System.Console.ReadLine();

            try
            {
                int[] nums = Array.ConvertAll(selectionIndexes.Split(','), int.Parse); //parse by comma
                foreach (int num in nums) //find key to index from user
                {
                    var item = allmethods.ElementAt(num - 1);
                    selectedMethodsID.Add(item.Key); //save ID
                }
            }
            catch
            {
                //just in case of inserted non-sence
                System.Console.WriteLine("\t Invalid input! Using IDs 301, 302");
                return new List<int>() { 301, 302 };
            }

            //TODO: Add mixed order

            System.Console.WriteLine(String.Format("\r\tSelected: {0}", string.Join(",", selectedMethodsID)));
            return selectedMethodsID;
        }

        public static int HowLongIsTransferInMs(string messageEncrypted, List<int> stegoMethods)
        {
            //how many bits have messageEncrypted
            int bitsInMessage = DataOperations.MessageASCIItoBitLenght(messageEncrypted);

            //how much space is in stegoMethods
            int spaceInOneMethod = 3; //estimation TODO exactly!
            NetSteganography.GetMethodCapacity(0); //TODO not done...

            int channelSize = stegoMethods.Count * spaceInOneMethod;
            int transportsNeeded = bitsInMessage / channelSize;

            //TODO how much time is needed - take from NetSenderClient public values...
            //TODO parse NetSteganography methods strings " - Xb"

            /* wireshark log:            
               750,859650   packet 1
               750,344017   packet 2
               ---------
               000,515633 when 500 is waiting time then 15 633 what mean 15,633 ms per message*/
            int bulgarianConstant = 10; //"basically anything which makes your result correct"
            int neededTimeInMs = transportsNeeded * 16 * bulgarianConstant;

            //multiply by "some" constant as underestimation
            neededTimeInMs = (int)(neededTimeInMs * 1.25);

            return neededTimeInMs;
        }
    }
}
