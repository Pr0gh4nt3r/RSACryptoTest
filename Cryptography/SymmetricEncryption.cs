using System.IO;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace Cryptography
{
    public class SymmetricEncryption
    {
        internal static byte[] EncryptPrivateKey(PrivateKey privateKey, string password)
        {
            using Aes aes = Aes.Create();
            aes.Key = GenerateKeyFromPassword(password, aes.KeySize / 8);
            aes.GenerateIV();

            using var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
            using var ms = new MemoryStream();
            ms.Write(aes.IV, 0, aes.IV.Length);
            using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
            using (var bw = new BinaryWriter(cs))
            {
                // Schreibe N und d in den Stream
                Helpers.WriteBigInteger(bw, privateKey.N);
                Helpers.WriteBigInteger(bw, privateKey.d);
            }

            return ms.ToArray();
        }

        internal static PrivateKey DecryptPrivateKey(byte[] encryptedPrivateKey, string password)
        {
            using Aes aes = Aes.Create();
            aes.Key = GenerateKeyFromPassword(password, aes.KeySize / 8);

            using var ms = new MemoryStream(encryptedPrivateKey);
            byte[] iv = new byte[aes.IV.Length];
            ms.Read(iv, 0, iv.Length);
            aes.IV = iv;

            using var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
            using var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
            using var br = new BinaryReader(cs);
            // Lies N und d aus dem Stream
            BigInteger n = Helpers.ReadBigInteger(br);
            BigInteger d = Helpers.ReadBigInteger(br);

            return new PrivateKey(n, d);
        }

        private static byte[] GenerateKeyFromPassword(string password, int keySize)
        {
            return SHA256.HashData(Encoding.UTF8.GetBytes(password)).Take(keySize).ToArray();
        }

        // Erzeugung eines AES-Schlüssels
        public static byte[] GenerateAESKey()
        {
            int keySizeInBytes = 256 / 8;
            byte[] key = new byte[keySizeInBytes];

            // RandomNumberGenerator verwenden für kryptographisch sicheren Zufall
            RandomNumberGenerator.Fill(key); // Füllt das Byte-Array mit zufälligen Werten

            return key;
        }

        // Verschlüsseln einer Nachricht mit AES
        public static byte[] Encrypt(string plainText, byte[] key)
        {
            using Aes aesAlg = Aes.Create();
            aesAlg.Key = key;
            aesAlg.GenerateIV(); // Initialisierungsvektor (IV) generieren

            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            using MemoryStream msEncrypt = new();
            // Speichern Sie das IV zuerst
            msEncrypt.Write(aesAlg.IV, 0, aesAlg.IV.Length);

            using (CryptoStream csEncrypt = new(msEncrypt, encryptor, CryptoStreamMode.Write))
            {
                using StreamWriter swEncrypt = new(csEncrypt);
                swEncrypt.Write(plainText);
            }

            return msEncrypt.ToArray(); // Zurückgeben des verschlüsselten Bytes inkl. IV
        }

        // Entschlüsseln einer Nachricht mit AES
        public static string Decrypt(byte[] cipherText, byte[] key)
        {
            using Aes aesAlg = Aes.Create();
            using MemoryStream msDecrypt = new MemoryStream(cipherText);
            byte[] iv = new byte[16]; // AES-Blockgröße für IV
            msDecrypt.Read(iv, 0, iv.Length); // IV aus dem verschlüsselten Text extrahieren

            aesAlg.Key = key;
            aesAlg.IV = iv;

            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            using CryptoStream csDecrypt = new(msDecrypt, decryptor, CryptoStreamMode.Read);
            using StreamReader srDecrypt = new(csDecrypt);

            return srDecrypt.ReadToEnd(); // Rückgabe des entschlüsselten Textes
        }
    }
}
