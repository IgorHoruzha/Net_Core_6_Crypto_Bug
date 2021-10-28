using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Net_Core_6_Crypto_Bug.Code_Examples
{
    internal class Crypo_New
    {

        // This constant is used to determine the keysize of the encryption algorithm in bits.
        // We divide this by 8 within the code below to get the equivalent number of bytes.
        private const int Keysize = 128;

        // This constant determines the number of iterations for the password bytes generation function.
        private const int DerivationIterations = 5000;

        public static string Encrypt(string to_encrypt, string key)
        {
            byte[] data = Encoding.Default.GetBytes(to_encrypt);
            byte[] crypted = Encrypt(data, key);
            return JsonSerializer.Serialize(crypted);
        }

        public static string Decrypt(String cryptedText, string key)
        {
            byte[] data = JsonSerializer.Deserialize<byte[]>(cryptedText) ?? throw new ArgumentNullException(cryptedText);
            byte[] crypted = Decrypt(data, key);

            var result = Encoding.Default.GetString(crypted);

            return result;
        }

        public static byte[] Encrypt(byte[] plainTextBytes, string passPhrase)
        {
            // Salt and IV is randomly generated each time, but is preprended to encrypted cipher text
            // so that the same Salt and IV values can be used when decrypting.  
            var saltStringBytes = Generate256BitsOfRandomEntropy();
            var ivStringBytes = Generate256BitsOfRandomEntropy();

            using var password = new Rfc2898DeriveBytes(passPhrase, saltStringBytes, DerivationIterations);
            var keyBytes = password.GetBytes(Keysize / 8);

            Aes aes = Aes.Create();
            aes.BlockSize = 128;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            using var encryptor = aes.CreateEncryptor(keyBytes, ivStringBytes);
            using var memoryStream = new MemoryStream();
            using var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write);
            cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);
            cryptoStream.FlushFinalBlock();
            // Create the final bytes as a concatenation of the random salt bytes, the random iv bytes and the cipher bytes.
            var cipherTextBytes = saltStringBytes;
            cipherTextBytes = cipherTextBytes.Concat(ivStringBytes).ToArray();
            cipherTextBytes = cipherTextBytes.Concat(memoryStream.ToArray()).ToArray();
            memoryStream.Close();
            cryptoStream.Close();
            return cipherTextBytes;
        }

        public static byte[] Decrypt(byte[] cipherTextBytesWithSaltAndIv, string passPhrase)
        {
            // Get the complete stream of bytes that represent:
            // [32 bytes of Salt] + [32 bytes of IV] + [n bytes of CipherText]

            // Get the saltbytes by extracting the first 32 bytes from the supplied cipherText bytes.
            var saltStringBytes = cipherTextBytesWithSaltAndIv.Take(Keysize / 8).ToArray();
            // Get the IV bytes by extracting the next 32 bytes from the supplied cipherText bytes.
            var ivStringBytes = cipherTextBytesWithSaltAndIv.Skip(Keysize / 8).Take(Keysize / 8).ToArray();
            // Get the actual cipher text bytes by removing the first 64 bytes from the cipherText string.
            var cipherTextBytes = cipherTextBytesWithSaltAndIv.Skip((Keysize / 8) * 2).Take(cipherTextBytesWithSaltAndIv.Length - ((Keysize / 8) * 2)).ToArray();

            using var password = new Rfc2898DeriveBytes(passPhrase, saltStringBytes, DerivationIterations);
            var keyBytes = password.GetBytes(Keysize / 8);
            Aes aes = Aes.Create();          
            aes.BlockSize = 128;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            using var decryptor = aes.CreateDecryptor(keyBytes, ivStringBytes);
            using var memoryStream = new MemoryStream(cipherTextBytes);
            using var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);
            var plainTextBytes = new byte[cipherTextBytes.Length];
            var decryptedByteCount = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);
            memoryStream.Close();
            cryptoStream.Close();
            return plainTextBytes[0..decryptedByteCount];
        }

        private static byte[] Generate256BitsOfRandomEntropy()
        {
            //var randomBytes = RandomNumberGenerator.GetBytes(16); //Todo: Commented because it is impossible to do on .net 5;
            //return randomBytes;

            var randomBytes = new byte[16]; // 32 Bytes will give us 256 bits.
            using (var rngCsp = new RNGCryptoServiceProvider())
            {
                // Fill the array with cryptographically secure random bytes.
                rngCsp.GetBytes(randomBytes);
            }
            return randomBytes;
        }

    }
}
