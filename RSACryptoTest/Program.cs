using Cryptography;
using System;
using System.Diagnostics;

namespace RSACryptoTest
{
    internal class Program
    {
        private const ConsoleColor white = ConsoleColor.White;
        private const ConsoleColor yellow = ConsoleColor.Yellow;
        private const ConsoleColor red = ConsoleColor.Red;
        private const ConsoleColor green = ConsoleColor.Green;
        private const ConsoleColor blue = ConsoleColor.Blue;

        static void Main(string[] args)
        {
            int keySize = 0;
            bool parsed = false;

            do
            {
                Console.Write("Geben Sie die gewünschte Schlüssellänge an (leer = Standard 4096 Bit): ");
                string input = Console.ReadLine();
                if (string.IsNullOrEmpty(input))
                    break;
                _ = int.TryParse(input, out keySize);
                if (keySize > 0)
                    parsed = true;
            }
            while (!parsed);

            Console.ForegroundColor = yellow;
            Console.WriteLine("Erzeuge Schlüsselpaar...");

            Stopwatch stopwatch = new();
            stopwatch.Start();

            RSACryptoServiceProvider rsa = keySize > 0 ? new(keySize) : new();

            stopwatch.Stop();

            Console.WriteLine($"Initialisierungsdauer: {stopwatch.Elapsed.Minutes}:{stopwatch.Elapsed.Seconds}.{stopwatch.Elapsed.Milliseconds}");
            Console.Write("Schütze deinen privaten Schlüssel mit einem Passwort, wenn gewünscht (leer = keine Verschlüsselung): ");

            string encPass = Helpers.ReadPassword();

            RSAParameters para = string.IsNullOrEmpty(encPass) ? rsa.ExportParameters(true) : rsa.ExportParameters(true, encPass);

            byte[] aesKey = SymmetricEncryption.GenerateAESKey();
            byte[] encryptedAESKey = RSACryptoServiceProvider.Encrypt(aesKey, para);

            Console.ForegroundColor = white;
            Console.WriteLine("\n\nIhr privater Schlüssel lautet:");
            Console.ForegroundColor = red;
            Console.WriteLine(para.PrivateKey != null ? BitConverter.ToString(para.PrivateKey) : BitConverter.ToString(para.EncryptedPrivateKey));

            Console.ForegroundColor = white;
            Console.WriteLine("Ihr öffentlicher Schlüssel lautet:");
            Console.ForegroundColor = green;
            Console.WriteLine(BitConverter.ToString(para.PublicKey));

            Console.ForegroundColor = blue;
            Console.Write("\nGib deinen zu verschlüsselnden Text ein: ");
            Console.ForegroundColor = white;

            string originalMessage = Console.ReadLine();
            byte[] encryptedMassage = SymmetricEncryption.Encrypt(originalMessage, aesKey);

            Console.ForegroundColor = blue;
            Console.Write("\nDer verschlüsselte Text: ");
            Console.ForegroundColor = green;
            Console.WriteLine(BitConverter.ToString(encryptedMassage));

            Console.ForegroundColor = white;
            Console.Write("\nZum entschlüsseln Passwort eingeben oder Enter drücken: ");
            
            string decPass = Helpers.ReadPassword();
            byte[] decryptedAESKey;

            try
            {
                decryptedAESKey = string.IsNullOrEmpty(decPass) ? RSACryptoServiceProvider.Decrypt(encryptedAESKey, para) : RSACryptoServiceProvider.Decrypt(encryptedAESKey, para, decPass);
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = red;
                Console.WriteLine($"Fehler beim Entschlüsseln des AES-Schlüssels: {ex.Message}");
                return;
            }

            string decryptedMessage = SymmetricEncryption.Decrypt(encryptedMassage, decryptedAESKey);

            Console.WriteLine();
            Console.ForegroundColor = blue;
            Console.Write("Der entschlüsselte Text: ");
            Console.ForegroundColor = white;
            Console.WriteLine(decryptedMessage);
        }
    }
}
