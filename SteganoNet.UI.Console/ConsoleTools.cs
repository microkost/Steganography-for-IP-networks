using System;
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
            List<Tuple<string, string>> ipv4localadd = NetDevice.GetIPv4addressesAndDescriptionLocal();
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
                if (ipv4localadd.Count <= 0)
                    return null; //"0.0.0.0";
                else
                    return ipv4localadd[0].Item1;
            }
        }

        public static void WriteInfoConsole(object nn) //printing output from console
        {
            INetNode mm = (INetNode)(nn); //retype //TODO more than hope = try-catch            
            try
            {
                System.Console.WriteLine("\t>{0}", mm.Messages.Dequeue());
            }
            catch
            {
                //System.Console.WriteLine("\t> ");
                Thread.Sleep(100);
            }
        }

        internal static List<int> SelectStegoMethods()
        {
            Dictionary<int, string> allmethods = NetSteganography.GetListStegoMethodsIdAndKey();
            List<int> selectedMethodsID = new List<int>();
            System.Console.WriteLine("\tSelect suitable steganoghraphy methods: ");

            for (int i = 0; i < allmethods.Count; i++) //method printer
            {
                var item = allmethods.ElementAt(i);
                System.Console.WriteLine(String.Format("\t\t{0}. {1} (id: {2})", i + 1, item.Value, item.Key));
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

            System.Console.WriteLine(String.Format("\r\tSelected: {0}", string.Join(",", selectedMethodsID)));
            return selectedMethodsID;
        }
    }
}
