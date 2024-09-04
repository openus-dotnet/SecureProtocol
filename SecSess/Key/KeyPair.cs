using System.Security.Cryptography;

namespace SecSess.Key
{
    /// <summary>
    /// Asymmetric key pair type
    /// </summary>
    public class KeyPair
    {
        /// <summary>
        /// Public keys paired with private keys
        /// </summary>
        public required PublicKey PublicKey { get; set; }
        /// <summary>
        /// Private keys paired with public keys
        /// </summary>
        public required PrivateKey PrivateKey { get; set; }

        /// <summary>
        /// Generate a new RSA key pair
        /// </summary>
        /// <returns></returns>
        public static KeyPair GenerateRSA()
        {
            RSA rsa = RSA.Create(4096);

            return new KeyPair()
            {
                PrivateKey = new PrivateKey(rsa.ExportParameters(true)),
                PublicKey = new PublicKey(rsa.ExportParameters(false)),
            };
        }
    }
}
