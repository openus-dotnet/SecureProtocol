using SecSess.Interface;
using SecSess.Key;
using System.Security.Cryptography;

namespace SecSess.Secure
{
    /// <summary>
    /// Custom asymmetric algorighm wrapper
    /// </summary>
    internal class Asymmetric
    {
        /// <summary>
        /// Asymmetric algorithm that actually works
        /// </summary>
        public AsymmetricAlgorithm? AsymmetricAlgorithm { get; private set; }

        /// <summary>
        /// Asymmetric algorithm to use
        /// </summary>
        public Algorithm.Asymmetric Algorithm { get; private set; }

        /// <summary>
        /// Create an asymmetric algorithm wrapper with the given key
        /// </summary>
        /// <param name="param"> Asymmetric algorithm parameter</param>
        /// <param name="algorithm"> Asymmetric algorithm to use</param>
        public Asymmetric(AsymmetricKeyBase param, Algorithm.Asymmetric algorithm)
        {
            Algorithm = algorithm;

            switch (algorithm)
            {
                case Secure.Algorithm.Asymmetric.None:
                    AsymmetricAlgorithm = null; 
                    break;
                case Secure.Algorithm.Asymmetric.RSA:
                    AsymmetricAlgorithm = RSA.Create(param.InnerRSA); 
                    break;
                default:
                    throw new InvalidOperationException("Use invalid symmetric algorithm");
            }
        }

        /// <summary>
        /// Encrypt to use asymmetric algorithm
        /// </summary>
        /// <param name="data">Will encrypt data</param>
        /// <returns>Encrypted data</returns>
        public byte[] Encrypt(byte[] data) 
        {
            switch (Algorithm)
            {
                case Secure.Algorithm.Asymmetric.RSA:
                    return (AsymmetricAlgorithm as RSA)!.Encrypt(data, RSAEncryptionPadding.Pkcs1);
                default:
                    throw new InvalidOperationException("Use invalid symmetric algorithm");
            }
        }

        /// <summary>
        /// Decrypt to use asymmetric algorithm
        /// </summary>
        /// <param name="data">Will decrypt data</param>
        /// <returns>Decrypted data</returns>
        public byte[] Decrypt(byte[] data)
        {
            switch (Algorithm)
            {
                case Secure.Algorithm.Asymmetric.RSA:
                    return (AsymmetricAlgorithm as RSA)!.Decrypt(data, RSAEncryptionPadding.Pkcs1);
                default:
                    throw new InvalidOperationException("Use invalid symmetric algorithm");
            }
        }
    }
}
