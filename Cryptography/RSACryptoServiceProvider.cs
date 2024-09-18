using System.Numerics;

namespace Cryptography
{
    public class RSACryptoServiceProvider
    {
        private readonly int _keySize;
        private readonly RSAParameters _parameters;

        public int KeySize => _keySize;

        public RSACryptoServiceProvider()
        {
            _keySize = 2048;
            _parameters = CreateKeyPair();
        }

        public RSACryptoServiceProvider(int KeySize)
        {
            _keySize = KeySize;
            _parameters = CreateKeyPair();
        }

        public RSAParameters ExportParameters(bool includePrivateParameters, string password = null)
        {
            if (includePrivateParameters)
            {
                if (string.IsNullOrEmpty(password))
                {
                    return new RSAParameters(_parameters.PrivateKey, _parameters.PublicKey);
                }
                else
                {
                    // Verschlüsselung des privaten Schlüssels mit dem Passwort
                    _parameters.EncryptPrivateKey(password);
                    return new RSAParameters(_parameters.EncryptedPrivateKey, _parameters.PublicKey);
                }
            }
            else
            {
                return new RSAParameters(_parameters.PublicKey);
            }
        }

        public static byte[] Encrypt(byte[] data, RSAParameters rsaKeyInfo)
        {
            var publicKey = Helpers.GetKeyFromByteArray(rsaKeyInfo.PublicKey);

            BigInteger m = new(data);
            BigInteger c = BigInteger.ModPow(m, publicKey.de, publicKey.N);
            return c.ToByteArray();
        }

        public static byte[] Decrypt(byte[] data, RSAParameters rsaKeyInfo, string password = null)
        {
            if (!string.IsNullOrEmpty(password))
            {
                // Entschlüsselung des privaten Schlüssels mit dem Passwort
                rsaKeyInfo.DecryptPrivateKey(password);
            }

            var privateKey = Helpers.GetKeyFromByteArray(rsaKeyInfo.PrivateKey);

            BigInteger c = new(data);
            BigInteger m = BigInteger.ModPow(c, privateKey.de, privateKey.N);
            return m.ToByteArray();
        }

        private RSAParameters CreateKeyPair()
        {
            BigInteger p = OpenAIRandomPrime.RandomPrime.GeneratePrime(_keySize / 2);
            BigInteger q = OpenAIRandomPrime.RandomPrime.GeneratePrime(_keySize / 2);
            BigInteger N = p * q;
            BigInteger phi = (p - 1) * (q - 1);
            BigInteger e = 65537;
            BigInteger d = GetPK(e, phi);
            PublicKey pk = new(N, e);
            PrivateKey sk = new(N, d);
            return new RSAParameters(sk, pk);
        }

        /// <summary>
        /// Berechnet mithilfe des Erweiterten Euklidischen Algorithmus das modulare Inverse von e modulo phi
        /// </summary>
        /// <param name="e"></param>
        /// <param name="phi"></param>
        /// <returns>Gibt den berechneten privaten Schlüssel zurück</returns>
        private static BigInteger GetPK(BigInteger e, BigInteger phi)
        {
            BigInteger i = phi, v = 0, d = 1; // v = Koeffizient des modularen Inversen | d = aktueller Wert der Berechnung (ggT)

            while (e > 0)
            {
                BigInteger t = i / e, x = e; // Quotient t wird berechnet
                e = i % x; // e = Rest i / x
                i = x; // i = x (vorheriger Wert von e)
                x = d;
                d = v - (t * x); // d wird auf Basis von v und t (aktueller Quotient) neu berechnet
                v = x; // v = x (vorheriger Wert von d)
            }

            v %= phi; // stellt sicher, dass v innerhalb von 0 bis phi - 1 liegt

            if (v < 0)
                v = (v + phi) % phi; // addiert phi zu v um sicherzustellen, dass v positiv ist

            return v;
        }
    }
}
