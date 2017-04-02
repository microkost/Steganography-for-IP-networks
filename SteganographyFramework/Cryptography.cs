using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SteganographyFramework
{
    public static class Cryptography
    {
        private const int bitsForChar = 8;

        public static string doCrypto(string input) //unimplemented cryptography for easier implementation later
        {
            return input;
        }

        public static string stringASCII2BinaryNumber(string input) //convert string to binary number
        {
            if (!IsASCII(input)) //protection
                return null;
                
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

        public static string binaryNumber2stringASCII(string input) //convert binary number to string
        {
            /*
            foreach(char c in input) //testing binary value
            {
                if (c != '0' || c != '1')
                    return null;
            }
            */

            List<string> binNumToConvert = input.SplitInParts(bitsForChar).ToList();
            string result = "";
            foreach(string num in binNumToConvert)
            {
                char c = (char)Convert.ToInt32(num, 2);
                result += c;
            }

            return result;
        }

        public static UInt16? binString2Int16(string input) //unnessesary, remove, confusing
        {
            if (input.Count() > 16)
                return null;

            try
            {                    
                return Convert.ToUInt16(input, 2);
            }
            catch
            {
                return null;
            }
        }

        /*
        public static uint? string2StegoNumber(string inputChars, int howManyBitsMin8) //get number from message
        {
            if (howManyBitsMin8 != 8 || howManyBitsMin8 != 16 || howManyBitsMin8 != 32 || howManyBitsMin8 != 64) //check size
                return null;

            int numofchars = howManyBitsMin8 / bitsForChar; 
            if(inputChars.Length > numofchars)
                return null;

            //number of chars is lower than available space

            //number of chars is same as available space

            String result = "";
            char[] array = inputChars.ToCharArray();
            for (int i = 0; i < numofchars; i++) //test size! //possible to do in reverse order, just for "cryptography"
            {
                char number = array[i]; //get number from char
                string binValue = Convert.ToString(number, 2);  //convert to binary
                binValue = binValue.PadLeft(8, '0');            //padding
                result += binValue;
            }

            Console.WriteLine(result);
            int final = Convert.ToInt32(result, 2);
            return (UInt32)final;

            //number of chars is higher then space

        }


        public static string stegoNumber2string(uint binnum, int HowManyBits)
        {
            if (HowManyBits % 2 != 0)
                return null;

            int numofchars = HowManyBits / 8;
            //number of chars is lower than available space
            //TODO

            //number of chars is same as available space
            string binValue = Convert.ToString(binnum, 2);  //convert to binary
            binValue = binValue.PadLeft(HowManyBits, '0'); //padding

            List<string> charsInBin = new List<string>();
            charsInBin = binValue.SplitInParts(8).ToList(); //divide into parts

            string final = "";
            foreach (string s in charsInBin)
            {
                char c = (char)Convert.ToInt32(s, 2);
                final += c;
            }

            return final;

            //number of chars is higher then space
            //TODO

        }
        */

        public static IEnumerable<String> SplitInParts(this String s, Int32 partLength) //splits string after every n char //converts to list by using .ToList()
        {
            //source: http://stackoverflow.com/questions/4133377/splitting-a-string-number-every-nth-character-number
            if (s == null)
                throw new ArgumentNullException("s");
            if (partLength <= 0)
                throw new ArgumentException("Part length has to be positive.", "partLength");

            for (var i = 0; i < s.Length; i += partLength)
                yield return s.Substring(i, Math.Min(partLength, s.Length - i));
        }

        public static bool IsASCII(this string value) //for testing ascii values
        {
            //source http://stackoverflow.com/questions/1522884/c-sharp-ensure-string-contains-only-ascii
            // ASCII encoding replaces non-ascii with question marks, so we use UTF8 to see if multi-byte sequences are there
            return Encoding.UTF8.GetByteCount(value) == value.Length;
        }

    }
}
