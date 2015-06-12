using System;
using System.IO;
using System.Security.Cryptography;

namespace Rijndeal_Encryption_Decryption
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
              
              var str = "pass@word1";

                for (int i = 0; i < 1000; i++)
                {
                    using (var myRijndael = Rijndael.Create())
                    {
                        //var cls = new CryptographyBase();
                        var cls = new CryptographyManaged();
                        // Encrypt the string to an array of bytes. 
                        byte[] encrypted = cls.Encrypt(str, myRijndael.Key, myRijndael.IV);

                        // Decrypt the bytes to a string. 
                        string roundtrip = cls.Decrypt(encrypted, myRijndael.Key, myRijndael.IV);

                        //Display the original data and the decrypted data.
                        Console.WriteLine("Original:   {0}", str);
                        Console.WriteLine("Round Trip: {0}", roundtrip);
                        Console.WriteLine("");
                        Console.WriteLine("");
                    }
                }





            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
            
            
        }

       
    }
}
