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
        public const int bitsForChar = 8; //how long is char in bits //TODO PROP?
        private const int hashBitMultiplier = 2; //how long is hash (bitsForChar * this)

        //sender: convert ASCII to BINARY
        //sender: prepare string for sending (alignment x8) return list of <int>
        //sender: spliting key string, how to recognize gaps? probably not needed, bitsForChar is delimiter
        //sender: validation and hashing

        //receiver: reasemble and convert BINARY to ASCII
        //receiver: un alingment => string to list of <int>
        //receiver: delimiter determining => bitsForChar as settings
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

            //should be also converted to BASE64 to avoid problems with non-ASCII characters

            string binaryNumInString = "";
            for (int i = 0; i < input.Length; i++)
            {
                char number = input[i]; //get number from char
                string binValue = Convert.ToString(number, 2); //convert num to binary
                binValue = binValue.PadLeft(bitsForChar, '0'); //padding binary 
                binaryNumInString += binValue;
            }

            /*
            //string should not start with zero, intro zeros in bin string are useless
            while (binaryNumInString[0].Equals('0') && binaryNumInString.Length > 1)
            {
                binaryNumInString = binaryNumInString.Remove(0, 1); //cut first zero
            }
            */

            return binaryNumInString;
        }

        public static string BinaryNumber2stringASCII(string input) //convert binary number to string
        {
            List<string> binNumToConvert = input.SplitInParts(bitsForChar).ToList();
            string result = "";

            //should be also converted from BASE64 as avoiding problems with non-ASCII characters


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

        public static bool IsASCII(this string value) //for testing ascii values
        {
            //source http://stackoverflow.com/questions/1522884/c-sharp-ensure-string-contains-only-ascii
            //ASCII encoding replaces non-ascii with question marks, so we use UTF8 to see if multi-byte sequences are there
            return Encoding.UTF8.GetByteCount(value) == value.Length;
        }

        public static int MessageASCIItoBitLenght(string message) //returns bit size of message or 0 when error
        {
            string binaryMesssage = StringASCII2BinaryNumber(message);
            if (binaryMesssage == null) { return 0; };

            return binaryMesssage.Count();
        }

        public static string ErrorDetectionASCIIFromClean(string message) //used by client to put redundancy for SENDING
        {
            //consistency check appended to string before converstion to binary https://en.wikipedia.org/wiki/Error_detection_and_correction

            //CalculateHash()
            string hashForMessage = CalculateHash(message);
            string hashSub = "";
            try
            {
                hashSub = hashForMessage.Substring(0, hashBitMultiplier * bitsForChar);
            }
            catch
            {
                //if message is short and hash is not enought long
                hashSub = hashForMessage.PadLeft(hashBitMultiplier * bitsForChar, '0');
            }

            return message + hashSub;

            //CalculateCrc32()
            //TODO method and selector
        }

        public static string ErrorDetectionASCII2Clean(string messageWithRedundancy) //used by server to check RECEIVED
        {
            //consistency check removed from received message, returns consistent message 

            try //CalculateHash variant
            {
                //cut off hash and pure message
                string hashReceived = messageWithRedundancy.Substring(messageWithRedundancy.Length - (hashBitMultiplier * bitsForChar));
                string message = ErrorDetectionCutHashOut(messageWithRedundancy);
                string hashForMessage = CalculateHash(message);
                string hashSub = "";
                try
                {
                    hashSub = hashForMessage.Substring(0, hashBitMultiplier * bitsForChar); //cut calculated hash
                }
                catch
                {
                    //if message is short and hash is not enought long
                    hashSub = hashForMessage.PadLeft(hashBitMultiplier * bitsForChar, '0');
                }

                if (hashReceived.Equals(hashSub))
                {
                    return message;
                }
                else
                {
                    return null;
                }
            }
            catch
            {
                return null; //when corrupted
            }
        }

        public static string ErrorDetectionCutHashOut(string messageWithRedundancy)
        {            
            if(messageWithRedundancy.Length <= 0)
            {
                return ""; //obviosly could come zero lenght
            }

            //cuts off hash, used for user outputs
            try
            {
                return messageWithRedundancy.Substring(0, messageWithRedundancy.Length - (hashBitMultiplier * bitsForChar));
            }
            catch //in case of failure
            {
                return messageWithRedundancy;
            }

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

        public static string CalculateCrc32(string input)
        {
            //source https://github.com/damieng/DamienGKit/blob/master/CSharp/DamienG.Library/Security/Cryptography/Crc32.cs
            throw new NotImplementedException();
        }
    }
}
