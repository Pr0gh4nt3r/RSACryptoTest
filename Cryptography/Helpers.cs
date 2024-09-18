using System;
using System.IO;
using System.Numerics;

namespace Cryptography
{
    public class Helpers
    {
        internal static byte[] ConvertKeyToByteArray(BigInteger N, BigInteger de)
        {
            using var ms = new MemoryStream();
            using (var bw = new BinaryWriter(ms))
            {
                // Schreibe N und d/e in den Stream
                WriteBigInteger(bw, N);
                WriteBigInteger(bw, de);
            }

            return ms.ToArray();
        }

        internal static (BigInteger N, BigInteger de) GetKeyFromByteArray(byte[] key)
        {
            using var ms = new MemoryStream(key);
            using var br = new BinaryReader(ms);
            // Lies N und d/e aus dem Stream
            BigInteger N = ReadBigInteger(br);
            BigInteger de = ReadBigInteger(br);
            return (N, de);
        }

        internal static void WriteBigInteger(BinaryWriter writer, BigInteger value)
        {
            byte[] data = value.ToByteArray(isUnsigned: true, isBigEndian: true);
            writer.Write(data.Length);  // Schreibe die Länge des BigInteger-Arrays
            writer.Write(data);
        }

        internal static BigInteger ReadBigInteger(BinaryReader reader)
        {
            int length = reader.ReadInt32();  // Lies die Länge des BigInteger-Arrays
            byte[] data = reader.ReadBytes(length);
            return new BigInteger(data, isUnsigned: true, isBigEndian: true);
        }

        public static string ReadPassword()
        {
            string password = string.Empty;
            ConsoleKeyInfo key;

            do
            {
                key = Console.ReadKey(true); // true bedeutet, dass die Eingabe nicht angezeigt wird

                // Wenn die Eingabe keine Enter-Taste ist, füge das Zeichen hinzu
                if (key.Key != ConsoleKey.Enter)
                {
                    // Maskiere das Zeichen mit einem Sternchen (*)
                    if (key.Key != ConsoleKey.Backspace)
                    {
                        password += key.KeyChar;
                        Console.Write("*"); // Zeige ein Maskierungszeichen an
                    }
                    else if (password.Length > 0)
                    {
                        // Entferne das letzte Zeichen, wenn Backspace gedrückt wird
                        password = password[..^1]; // Substring(0, password.Length - 1)
                        Console.Write("\b \b"); // Lösche das letzte Zeichen auf der Konsole
                    }
                }
            } while (key.Key != ConsoleKey.Enter); // Eingabe endet mit Enter

            return password;
        }
    }
}
