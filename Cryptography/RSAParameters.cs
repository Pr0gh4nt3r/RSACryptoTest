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

    public class PublicKey
    {
        public readonly BigInteger N;
        public readonly BigInteger e;

        public PublicKey(BigInteger N, BigInteger e)
        {
            this.N = N;
            this.e = e;
        }
    }

    public class PrivateKey
    {
        public readonly BigInteger N;
        public readonly BigInteger d;

        public PrivateKey(BigInteger N, BigInteger d)
        {
            this.N = N;
            this.d = d;
        }
    }
}
