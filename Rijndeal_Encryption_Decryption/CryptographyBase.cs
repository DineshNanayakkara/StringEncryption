using System;
using System.IO;
using System.Security.Cryptography;

namespace Rijndeal_Encryption_Decryption
{
    internal class CryptographyBase
    {
        [MTAThread]
        internal byte[] Encrypt(string plainText, byte[] key, byte[] IV)
        {
            // Check arguments. 
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (key == null || key.Length <= 0)
                throw new ArgumentNullException("key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("key");
            byte[] encrypted;
            // Create an Rijndael object 
            // with the specified key and IV. 
            using (var rijAlg = Rijndael.Create())
            {
                rijAlg.Key = key;
                rijAlg.IV = IV;


                // Create a decrytor to perform the stream transform.
                ICryptoTransform encryptor = rijAlg.CreateEncryptor(rijAlg.Key, rijAlg.IV);

                // Create the streams used for encryption. 
                MemoryStream msEncrypt = null;
                CryptoStream csEncrypt = null;
                try
                {
                    msEncrypt = new MemoryStream();
                    csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write);

                    using (var swEncrypt = new StreamWriter(csEncrypt))
                    {
                        //Write all data to the stream.
                        csEncrypt = null;
                        swEncrypt.Write(plainText);
                    }
                    encrypted = msEncrypt.ToArray();
                    msEncrypt.Flush();
                    msEncrypt = null;
                }
                finally
                {
                    if (csEncrypt != null)
                    {
                        csEncrypt.Dispose();
                    }
                    if (msEncrypt != null)
                    {
                        msEncrypt.Dispose();
                    }
                }
            }

            // Return the encrypted bytes from the memory stream. 
            return encrypted;

        }

        [MTAThread]
        internal string Decrypt(byte[] cipherText, byte[] key, byte[] IV)
        {
            // Check arguments. 
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (key == null || key.Length <= 0)
                throw new ArgumentNullException("key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("key");

            // Declare the string used to hold 
            // the decrypted text. 
            string plaintext = null;

            // Create an Rijndael object 
            // with the specified key and IV. 
            using (var rijAlg = Rijndael.Create())
            {
                rijAlg.Key = key;
                rijAlg.IV = IV;

                // Create a decrytor to perform the stream transform.
                ICryptoTransform decryptor = rijAlg.CreateDecryptor(rijAlg.Key, rijAlg.IV);

                // Create the streams used for decryption. 
                MemoryStream msDecrypt = null;
                CryptoStream csDecrypt = null;

                try
                {
                    msDecrypt = new MemoryStream(cipherText);
                    csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);

                    using (var srDecrypt = new StreamReader(csDecrypt))
                    {
                        //msDecrypt = null;
                        csDecrypt = null;
                        // Read the decrypted bytes from the decrypting stream 
                        // and place them in a string.
                        plaintext = srDecrypt.ReadToEnd();
                        msDecrypt.Flush();
                        msDecrypt = null;
                    }
                }
                finally
                {
                    if (csDecrypt != null)
                    {
                        csDecrypt.Dispose();
                    }
                    if (msDecrypt != null)
                    {
                        msDecrypt.Dispose();
                    }
                }
            }

            return plaintext;
        }
    }
}
