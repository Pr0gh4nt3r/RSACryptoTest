using System.Numerics;

namespace Cryptography
{
    public class RSAParameters
    {
        public readonly byte[] PublicKey;
        public byte[] PrivateKey { get; private set; }
        public byte[] EncryptedPrivateKey { get; private set; }

        public RSAParameters(PrivateKey privateKey, PublicKey publicKey)
        {
            PrivateKey = Helpers.ConvertKeyToByteArray(privateKey.N, privateKey.d);
            PublicKey = Helpers.ConvertKeyToByteArray(publicKey.N, publicKey.e);
        }

        public RSAParameters(byte[] encryptedPrivateKey, byte[] publicKey)
        {
            EncryptedPrivateKey = encryptedPrivateKey;
            PublicKey = publicKey;
        }

        public RSAParameters(byte[] publicKey)
        {
            PublicKey = publicKey;
        }


        public void EncryptPrivateKey(string password)
        {
            var (N, de) = Helpers.GetKeyFromByteArray(PrivateKey);
            EncryptedPrivateKey = SymmetricEncryption.EncryptPrivateKey(new(N, de), password);
            PrivateKey = null; // Lösche den unverschlüsselten privaten Schlüssel aus dem Speicher
        }

        public void DecryptPrivateKey(string password)
        {
            PrivateKey privateKey = SymmetricEncryption.DecryptPrivateKey(EncryptedPrivateKey, password);
            PrivateKey = Helpers.ConvertKeyToByteArray(privateKey.N, privateKey.d);
        }
    }

    public class PublicKey(BigInteger N, BigInteger e)
    {
        public readonly BigInteger N = N;
        public readonly BigInteger e = e;
    }

    public class PrivateKey(BigInteger N, BigInteger d)
    {
        public readonly BigInteger N = N;
        public readonly BigInteger d = d;
    }
}
