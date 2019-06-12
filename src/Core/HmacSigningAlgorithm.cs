namespace Security.HMAC
{
    using System;
    using System.Security;
    using System.Security.Cryptography;
    using System.Text;

    public delegate HMAC HmacAlgorithmFactory(byte[] secretBytes);

    public interface ISigningAlgorithm
    {
        string Sign(SecureString secret, string content);
    }

    public sealed class HmacSigningAlgorithm : ISigningAlgorithm
    {
        private readonly HmacAlgorithmFactory algorithmFactory;

        public HmacSigningAlgorithm(HmacAlgorithmFactory algorithmFactory)
        {
            this.algorithmFactory = algorithmFactory;
        }

        public string Sign(SecureString secret, string content)
        {
            byte[] contentBytes = Encoding.UTF8.GetBytes(content);
            byte[] secretBytes = secret.ToByteArray(Encoding.UTF8);

            byte[] signatureBytes;
            using (var hmac = algorithmFactory(secretBytes))
            {
                signatureBytes = hmac.ComputeHash(contentBytes);
            }

            // we need to remove unencrypted secret from memory
            Array.Clear(secretBytes, 0, secretBytes.Length);

            return Convert.ToBase64String(signatureBytes);
        }
    }
}