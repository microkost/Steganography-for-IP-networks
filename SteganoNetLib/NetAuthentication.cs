using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SteganoNetLib
{
    public static class NetAuthentication
    {
        //proves if oposite side is that who we think is it
        //uses logic of https://en.wikipedia.org/wiki/Challenge-Handshake_Authentication_Protocol

        public static string ChapChallenge(string secret) //NetSenderClient and vice versa
        {
            //generate and remember random string (should be binary and should be multiple of eight or bitsForChar sized)

            var length = 8;
            Random random = new Random();
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";                       
            string challenge = Enumerable.Repeat(chars, length).Select(s => s[random.Next(s.Length)]).ToArray().ToString();

            return DataOperations.StringASCII2BinaryNumber(challenge);
        }

        public static string ChapResponse(string message, string secret) //NetReceiverServer and vice versa
        {
            //make hash from received message and local secret
            return DataOperations.CalculateHash(message + secret);            
        }

        public static bool ChapAuthenticate(string messageReceived, string messageLocal, string secret) //NetSenderClient and vice versa
        {
            //compute: messageLocal + secret == messageReceived + secret

            if (DataOperations.CalculateHash(messageLocal + secret) == DataOperations.CalculateHash(messageReceived + secret))
                return true;
            else
                return false;
        }      

        //periodic reminder

        //closing handshake
    }
}
