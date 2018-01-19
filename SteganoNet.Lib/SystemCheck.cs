using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SteganoNet.Lib
{
    public static class SystemCheck //cannot have dependecies to anything from PcapDotNet!
    {
        public static bool AreSystemPrerequisitiesDone()
        {
            //testing availability of used libraries (needs to be in "view" layer because of dependencies of others
            //http://www.dependencywalker.com for debug

            //string AssemblyDirectory = Path.GetDirectoryName(Uri.UnescapeDataString(new UriBuilder(Assembly.GetExecutingAssembly().CodeBase).Path)); //source https://stackoverflow.com/questions/52797/how-do-i-get-the-path-of-the-assembly-the-code-is-in
            string AssemblyDirectory = AppDomain.CurrentDomain.BaseDirectory;
            try
            {
                //If WinPCap is installed then the following registry key should exist:
                //HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WinPcapInst

                //dotnetwinpcap.dll or WinPcap.dll
                System.Reflection.AssemblyName testAssembly1 = System.Reflection.AssemblyName.GetAssemblyName(AssemblyDirectory + "WinPcap.dll");
                System.Console.WriteLine("Yes, the WinPcap is installed on computer.");

                //FileNotFoundException: Could not load file or assembly 'PcapDotNet.Core.dll' or one of its dependencies. The specified module could not be found.
                System.Reflection.AssemblyName testAssembly2 = System.Reflection.AssemblyName.GetAssemblyName(AssemblyDirectory + "PcapDotNet.Core.dll");
                System.Console.WriteLine("Yes, the file PcapDotNet.Core.dll is in assembly.");

                //PcapDotNet.Base.dll
                //PcapDotNet.Core.Extensions.dll
                //PcapDotNet.Packets.dll

                return true;
            }
            catch (System.IO.FileNotFoundException)
            {
                System.Console.WriteLine("The file cannot be found.");
                return false;
            }
        }
    }
}
