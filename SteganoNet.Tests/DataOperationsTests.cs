using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Threading;

namespace SteganoNet.Tests
{
    [TestClass]
    public class DataOperationsTests
    {
        //[initialize]       

        [TestMethod]
        public void StringASCII2BinaryNumberTest()
        {
            //empty input
            var actual = SteganoNetLib.DataOperations.StringASCII2BinaryNumber("");
            Assert.AreEqual("", actual);

            //regular operation
            var expected = "0100100001100101011011000110110001101111001000000111011101101111011100100110110001100100";
            actual = SteganoNetLib.DataOperations.StringASCII2BinaryNumber("Hello world");
            Assert.AreEqual(expected, actual);

            //testing wrong input            
            actual = SteganoNetLib.DataOperations.StringASCII2BinaryNumber("Jyväskylä");
            Assert.AreEqual(null, actual);

            //add null test            
            try
            {
                actual = SteganoNetLib.DataOperations.StringASCII2BinaryNumber(null);
                Assert.Fail("An exception should have been thrown");
            }
            catch (ArgumentNullException)
            {
                Assert.AreEqual(1, 1); //System.ArgumentNullException: Parameter cannot be null.
            }
        }

        [TestMethod]
        public void BinaryNumber2stringASCIITest()
        {
            //empty input
            var actual = SteganoNetLib.DataOperations.BinaryNumber2stringASCII("");
            Assert.AreEqual("", actual);

            //regular operation
            actual = SteganoNetLib.DataOperations.BinaryNumber2stringASCII("0100100001100101011011000110110001101111001000000111011101101111011100100110110001100100");
            Assert.AreEqual("Hello world", actual);

            //testing wrong input
            //actual = SteganoNetLib.DataOperations.BinaryNumber2stringASCII("123ABC");
            //Assert.AreEqual("", actual);
            //System.FormatException: (NOT GOOD) reimplement method

            //testing null
            try
            {
                actual = SteganoNetLib.DataOperations.BinaryNumber2stringASCII(null);
                Assert.Fail("An exception should have been thrown");
            }
            catch (ArgumentNullException)
            {
                Assert.AreEqual(1, 1); //System.ArgumentNullException: Parameter cannot be null.
            }

        }

        [TestMethod]
        public void CalculateMD5HashTest()
        {
            //empty input

            //regular operation - it needs to be twice same(!)
            var actual = SteganoNetLib.DataOperations.CalculateMD5Hash("Hello world");
            Assert.AreEqual("3e25960a79dbc69b674cd4ec67a72c62", actual);
            Thread.Sleep(100); //0,1s
            actual = SteganoNetLib.DataOperations.CalculateMD5Hash("Hello world");
            Assert.AreEqual("3e25960a79dbc69b674cd4ec67a72c62", actual);

            //testing wrong input

            //testing null
        }

    }
}
