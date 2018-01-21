using Microsoft.Win32;
using System;
using System.Collections.Generic;

namespace SteganoNet.Lib
{
    public static class SystemCheck //cannot have dependecies to anything from PcapDotNet!
    {
        public static bool AreSystemPrerequisitiesDone() //testing availability of used libraries and dependencies on Windows
        {
            bool isEverythingOK = false;
            System.Reflection.AssemblyName testAssembly;
            //string AssemblyDirectory = Path.GetDirectoryName(Uri.UnescapeDataString(new UriBuilder(Assembly.GetExecutingAssembly().CodeBase).Path)); //source https://stackoverflow.com/questions/52797/how-do-i-get-the-path-of-the-assembly-the-code-is-in
            string AssemblyDirectory = AppDomain.CurrentDomain.BaseDirectory;

            try
            {
                bool winPcapFound = false;
                string registry_key = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
                using (Microsoft.Win32.RegistryKey key = Registry.LocalMachine.OpenSubKey(registry_key))
                {
                    foreach (string subkey_name in key.GetSubKeyNames())
                    {
                        //If WinPCap is installed then the following registry key should exist: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WinPcapInst
                        if (subkey_name.StartsWith("WinPcap")) //"WinPcapInst" to be specific...
                        {
                            winPcapFound = true;
                        }
                    }
                }

                if (winPcapFound == true)
                {
                    isEverythingOK = true;
                }
                else
                {
                    throw new KeyNotFoundException();
                }

            }
            catch (KeyNotFoundException)
            {
                System.Console.WriteLine(" The WinPcap is not installed on this computer.");
                return false;
            }
            try
            {
                testAssembly = System.Reflection.AssemblyName.GetAssemblyName(AssemblyDirectory + "PcapDotNet.Core.dll");
                //testAssembly = System.Reflection.AssemblyName.GetAssemblyName(AssemblyDirectory + "PcapDotNet.Base.dll");
                //testAssembly = System.Reflection.AssemblyName.GetAssemblyName(AssemblyDirectory + "PcapDotNet.Core.Extensions.dll");
                //testAssembly = System.Reflection.AssemblyName.GetAssemblyName(AssemblyDirectory + "PcapDotNet.Packets.dll");                
            }
            catch (System.IO.FileNotFoundException)
            {
                System.Console.WriteLine(" The PcapDotNet.*.dll cannot be found at " + AssemblyDirectory);
                return false;
            }

            if (isEverythingOK == true)
            {
                return true;
            }
            else
            {
                return false;
            }
        }
    }
}
