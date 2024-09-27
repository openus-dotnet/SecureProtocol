using Openus.Net.SecSess.Secure.Algorithm;
using System.Security.Cryptography;

namespace Openus.Net.SecSess.Secure.Wrapper
{
    /// <summary>
    /// Custom symmetric algorighm wrapper
    /// </summary>
    internal class Symmetric
    {
        /// <summary>
        /// Symmetric algorithm that actually works
        /// </summary>
        private SymmetricAlgorithm? _symmetric;

        /// <summary>
        /// Symmetric algorithm to use
        /// </summary>
        public SymmetricType Algorithm { get; private set; }

        /// <summary>
        /// Create an symmetric algorithm wrapper with the given key
        /// </summary>
        /// <param name="key"> Symmetric algorithm key</param>
        /// <param name="algorithm"> Symmetric algorithm to use</param>
        public Symmetric(byte[] key, SymmetricType algorithm)
        {
            Algorithm = algorithm;

            switch (algorithm)
            {
                case SymmetricType.None:
                    _symmetric = null;
                    break;
                case SymmetricType.DES:
                    _symmetric = DES.Create();
                    break;
                case SymmetricType.TripleDES:
                    _symmetric = TripleDES.Create();
                    break;
                case SymmetricType.AES:
                    _symmetric = Aes.Create();
                    break;
                default:
                    throw new InvalidOperationException("Use invalid symmetric algorithm.");
            }

            if (_symmetric != null)
            {
                _symmetric.Key = key;
            }
        }

        /// <summary>
        /// Encrypt data
        /// </summary>
        /// <param name="data">Data to be encrypted</param>
        /// <param name="iv">Initial vector</param>
        /// <returns>Encrypted data</returns>
        public byte[]? Encrypt(byte[] data, byte[] iv)
        {
            if (_symmetric == null)
            {
                return data;
            }

            byte[] dest = new byte[data.Length + (data.Length % BlockSize(Algorithm))];
            bool result = _symmetric.TryEncryptCbc(data, iv, dest, out int o, PaddingMode.Zeros);

            return result == true ? dest : null;
        }

        /// <summary>
        /// Decrypt data
        /// </summary>
        /// <param name="data">Data to be decrypted</param>
        /// <param name="iv">Initial vector</param>
        /// <returns>Decrypted data</returns>
        public byte[]? Decrypt(byte[] data, byte[] iv)
        {
            if (_symmetric == null)
            {
                return data;
            }

            byte[] dest = new byte[data.Length];
            bool result = _symmetric.TryDecryptCbc(data, iv, dest, out int o, PaddingMode.Zeros);

            return result == true ? dest : null;
        }

        /// <summary>
        /// Return symmetric key size for using algorithm
        /// </summary>
        /// <param name="algorithm">Symmetric algorithm to use</param>
        /// <returns></returns>
        public static int KeySize(SymmetricType algorithm)
        {
            switch (algorithm)
            {
                case SymmetricType.None:
                    return 0;
                case SymmetricType.DES:
                    return 8;
                case SymmetricType.TripleDES:
                    return 24;
                case SymmetricType.AES:
                    return 32;
                default:
                    throw new InvalidOperationException("Use invalid symmetric algorithm.");
            }
        }

        /// <summary>
        /// Return symmetric block size for using algorithm
        /// </summary>
        /// <param name="algorithm">Symmetric algorithm to use</param>
        /// <returns></returns>
        public static int BlockSize(SymmetricType algorithm)
        {
            switch (algorithm)
            {
                case SymmetricType.None:
                    return 0;
                case SymmetricType.DES:
                    return 8;
                case SymmetricType.TripleDES:
                    return 8;
                case SymmetricType.AES:
                    return 16;
                default:
                    throw new InvalidOperationException("Use invalid symmetric algorithm.");
            }
        }
    }
}
