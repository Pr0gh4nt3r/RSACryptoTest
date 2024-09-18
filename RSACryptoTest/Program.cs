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
                Console.Write("Geben Sie die gewünschte Schlüssellänge an (leer = Standard 2048 Bit): ");
                string input = Console.ReadLine();
                if (string.IsNullOrEmpty(input))
                    break;
                _ = int.TryParse(input, out keySize);
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
            string password = Helpers.ReadPassword();
            RSAParameters para = string.IsNullOrEmpty(password) ? rsa.ExportParameters(true) : rsa.ExportParameters(true, password);
            byte[] aesKey = SymmetricEncryption.GenerateAESKey();
            byte[] encryptedAESKey = RSACryptoServiceProvider.Encrypt(aesKey, para);
            Console.ForegroundColor = white;
            Console.WriteLine("Ihr privater Schlüssel lautet:");
            Console.ForegroundColor = red;
            Console.WriteLine(para.PrivateKey != null ? BitConverter.ToString(para.PrivateKey) : BitConverter.ToString(para.EncryptedPrivateKey));
            Console.ForegroundColor = white;
            Console.WriteLine("Ihr öffentlicher Schlüssel lautet:");
            Console.ForegroundColor = green;
            Console.WriteLine(BitConverter.ToString(para.PublicKey));
            Console.ForegroundColor = blue;
            Console.Write("Gib deinen zu verschlüsselnden Text ein: ");
            Console.ForegroundColor = white;
            string originalMessage = Console.ReadLine();
            byte[] encryptedMassage = SymmetricEncryption.Encrypt(originalMessage, aesKey);
            Console.ForegroundColor = blue;
            Console.Write("\nDer verschlüsselte Text: ");
            Console.ForegroundColor = green;
            Console.WriteLine(BitConverter.ToString(encryptedMassage));
            Console.ForegroundColor = white;
            Console.WriteLine("\nZum entschlüsseln Taste drücken...");
            Console.ReadLine();
            string decryptedMessage = SymmetricEncryption.Decrypt(encryptedMassage, aesKey);
            Console.ForegroundColor = blue;
            Console.Write("Der entschlüsselte Text: ");
            Console.ForegroundColor = white;
            Console.WriteLine(decryptedMessage);
            Console.ReadLine();
        }
    }
}
