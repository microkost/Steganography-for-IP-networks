using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace SteganoNetLib
{
    public static class DataOperations
    {
        private const int bitsForChar = 8; //how long is char in bits //TODO PROP?

        //sender: convert ASCII to BINARY
        //receiver: reasemble and convert to ASCII

        //sender: prepare string for sending (alignment x8) retrun list of <int>
        //receiver: un alingment => string to list of <int>

        //sender: spliting key string, how to recognize gaps? probably not needed, bitsForChar is delimiter
        //receiver: delimiter determining => bitsForChar as settings

        //sender: validation and hashing
        //receiver: hashing and validate

        public static string StringASCII2BinaryNumber(string input) //convert string to binary number
        {
            if (!IsASCII(input)) //protection
            {
                //var input2 = Regex.Replace(input, @"[^\u0020-\u007E]", string.Empty); //cut out non ascii chars as solution
                //input = input2;
                //if(!IsASCII(input)){return null}; //recheck... if 
                return null;
            }

            string binaryNumInString = "";
            for (int i = 0; i < input.Length; i++)
            {
                char number = input[i]; //get number from char
                string binValue = Convert.ToString(number, 2); //convert num to binary
                binValue = binValue.PadLeft(bitsForChar, '0'); //padding binary 
                binaryNumInString += binValue;
            }
            return binaryNumInString;
        }

        public static string BinaryNumber2stringASCII(string input) //convert binary number to string
        {
            List<string> binNumToConvert = input.SplitInParts(bitsForChar).ToList();
            string result = "";

            foreach (string num in binNumToConvert)
            {
                char c = ' ';
                try 
                {
                    c = (char)Convert.ToInt32(num, 2); //missing any input protection
                }
                catch
                {
                    //should be tested if result of conversion is ASCII like if(IsASCII)...?
                    return "message is non-stego";
                }

                if (c == '\0') //dont return end of char earlier!
                    continue;                

                result += c;
            }

            return result;
        }

        public static IEnumerable<String> SplitInParts(this String s, Int32 partLength) //splits string after every n char and converts to list by using .ToList()
        {
            //source: http://stackoverflow.com/questions/4133377/splitting-a-string-number-every-nth-character-number
            if (s == null)
                throw new ArgumentNullException(s, "Message to be splitted is null");
            if (partLength <= 0)
                throw new ArgumentException("Part length has to be positive.", "partLength");

            for (var i = 0; i < s.Length; i += partLength)
                yield return s.Substring(i, Math.Min(partLength, s.Length - i));
        }

        private static bool IsASCII(this string value) //for testing ascii values
        {
            //source http://stackoverflow.com/questions/1522884/c-sharp-ensure-string-contains-only-ascii
            // ASCII encoding replaces non-ascii with question marks, so we use UTF8 to see if multi-byte sequences are there
            return Encoding.UTF8.GetByteCount(value) == value.Length;
        }

        public static string CalculateHash(string input)
        {
            //source https://blogs.msdn.microsoft.com/csharpfaq/2006/10/09/how-do-i-calculate-a-md5-hash-from-a-string/
            //or to use CRC32 function

            MD5 md5 = System.Security.Cryptography.MD5.Create();
            byte[] inputBytes = System.Text.Encoding.ASCII.GetBytes(input);
            byte[] hash = md5.ComputeHash(inputBytes); //calculate MD5 hash from input

            StringBuilder sb = new StringBuilder(); // step 2, convert byte array to hex string
            for (int i = 0; i < hash.Length; i++)
            {
                sb.Append(hash[i].ToString("x2"));
            }

            return sb.ToString();
        }

        //crc or another consistency check appended to string...
        //public static string CalculateCrc32() https://github.com/damieng/DamienGKit/blob/master/CSharp/DamienG.Library/Security/Cryptography/Crc32.cs
    }
}
