using Openus.SecureProtocol.Secure.Algorithm;
using System.Security.Cryptography;

namespace Openus.SecureProtocol.Key.Asymmetric
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
        /// Asymmetric algorithm to use
        /// </summary>
        public required AsymmetricType Algorithm { get; set; }

        /// <summary>
        /// Generate a new RSA key pair
        /// </summary>
        /// <returns></returns>
        public static KeyPair GenerateRSA()
        {
            RSA rsa = RSA.Create(2048);

            return new KeyPair()
            {
                PrivateKey = new PrivateKey(AsymmetricType.RSA, rsa.ExportParameters(true)),
                PublicKey = new PublicKey(AsymmetricType.RSA, rsa.ExportParameters(false)),
                Algorithm = AsymmetricType.RSA,
            };
        }
    }
}
