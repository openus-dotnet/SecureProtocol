using Openus.SecureProtocol.Key.Asymmetric;
using Openus.SecureProtocol.Secure.Algorithm;
using Openus.SecureProtocol.Util;
using System.Security.Cryptography;

namespace Openus.SecureProtocol.Secure.Wrapper
{
    /// <summary>
    /// Custom asymmetric algorighm wrapper
    /// </summary>
    internal class Asymmetric
    {
        /// <summary>
        /// Asymmetric algorithm that actually works
        /// </summary>
        private AsymmetricAlgorithm? _asymmetric;

        /// <summary>
        /// Asymmetric algorithm to use
        /// </summary>
        public AsymmetricType Algorithm { get; private set; }

        /// <summary>
        /// Create an asymmetric algorithm wrapper with the given key
        /// </summary>
        /// <param name="param"> Asymmetric algorithm parameter</param>
        /// <param name="algorithm"> Asymmetric algorithm to use</param>
        public Asymmetric(BaseAsymmetricKey? param, AsymmetricType algorithm)
        {
            if (param == null ^ algorithm == AsymmetricType.None)
            {
                throw new SecSessException(ExceptionCode.InvalidCombination);
            }

            Algorithm = algorithm;

            switch (algorithm)
            {
                case AsymmetricType.None:
                    _asymmetric = null;

                    break;
                case AsymmetricType.RSA:
                    _asymmetric = RSA.Create(param!.InnerRSA);

                    break;
                default:
                    throw new SecSessException(ExceptionCode.InvalidAsymmetric);
            }
        }

        /// <summary>
        /// Encrypt to use asymmetric algorithm
        /// </summary>
        /// <param name="data">Will encrypt data</param>
        /// <returns>Encrypted data</returns>
        public byte[]? Encrypt(byte[] data)
        {
            switch (Algorithm)
            {
                case AsymmetricType.RSA:
                    byte[] result = new byte[BlockSize(Algorithm)];
                    bool b = (_asymmetric as RSA)!.TryEncrypt(data, result, RSAEncryptionPadding.Pkcs1, out int o);

                    return b == true ? result : null;
                default:
                    throw new SecSessException(ExceptionCode.InvalidAsymmetric);
            }
        }

        /// <summary>
        /// Decrypt to use asymmetric algorithm
        /// </summary>
        /// <param name="data">Will decrypt data</param>
        /// <returns>Decrypted data</returns>
        public byte[]? Decrypt(byte[] data)
        {
            switch (Algorithm)
            {
                case AsymmetricType.RSA:
                    byte[] result = new byte[BlockSize(Algorithm)];
                    bool b = (_asymmetric as RSA)!.TryDecrypt(data, result, RSAEncryptionPadding.Pkcs1, out int o);

                    return b == true ? result : null;
                default:
                    throw new SecSessException(ExceptionCode.InvalidAsymmetric);
            }
        }

        /// <summary>
        /// Get block size to use algorithm
        /// </summary>
        /// <param name="algorithm">Algorithm to use</param>
        /// <returns></returns>
        public static int BlockSize(AsymmetricType algorithm)
        {
            switch (algorithm)
            {
                case AsymmetricType.RSA:
                    return 256;
                default:
                    throw new SecSessException(ExceptionCode.InvalidAsymmetric);
            }
        }
    }
}
