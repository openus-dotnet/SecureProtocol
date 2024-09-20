using SecSess.Secure.Algorithm;
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
        /// Asymmetric algorithm to use
        /// </summary>
        public required Asymmetric Algorithm { get; set; }

        /// <summary>
        /// Generate a new RSA key pair
        /// </summary>
        /// <returns></returns>
        public static KeyPair GenerateRSA()
        {
            RSA rsa = RSA.Create(2048);

            return new KeyPair()
            {
                PrivateKey = new PrivateKey(Asymmetric.RSA, rsa.ExportParameters(true)),
                PublicKey = new PublicKey(Asymmetric.RSA, rsa.ExportParameters(false)),
                Algorithm = Asymmetric.RSA,
            };
        }
    }
}
