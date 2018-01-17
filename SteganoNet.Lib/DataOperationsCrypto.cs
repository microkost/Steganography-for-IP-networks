using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SteganoNetLib
{
    public static class DataOperationsCrypto
    {
        /*
         LIST of methods:
          default = cleartext
          0 = cleartext
         */

        public static string DoCrypto(string clearTextInput, int method = 0)
        {
            //NOT IN USE, just theoretical upgrade solution

            string secretTextOutput = "";
            if (method == 0)
            {
                secretTextOutput = clearTextInput;

            }
            else
            {
                secretTextOutput = clearTextInput;
            }

            return secretTextOutput;
        }

        public static string ReadCrypto(string cipherInput, int method = 0)
        {
            //NOT IN USE, just theoretical upgrade solution

            string clearTextOutput = "";
            if (method == 0)
            {
                clearTextOutput = cipherInput;

            }
            else
            {
                clearTextOutput = cipherInput;
            }

            return clearTextOutput;
        }

    }
}
