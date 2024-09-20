using System.Security.Cryptography;

namespace SecSess.Secure
{
    /// <summary>
    /// Custom symmetric algorighm wrapper
    /// </summary>
    internal class Symmetric
    {
        /// <summary>
        /// Symmetric algorithm that actually works
        /// </summary>
        private SymmetricAlgorithm? _algorithm;

        /// <summary>
        /// Symmetric algorithm to use
        /// </summary>
        public Algorithm.Symmetric Algorithm { get; private set; }

        /// <summary>
        /// Create an symmetric algorithm wrapper with the given key
        /// </summary>
        /// <param name="key"> Symmetric algorithm key</param>
        /// <param name="algorithm"> Symmetric algorithm to use</param>
        public Symmetric(byte[] key, Algorithm.Symmetric algorithm)
        {
            Algorithm = algorithm;

            switch (algorithm)
            {
                case Secure.Algorithm.Symmetric.None: 
                    _algorithm = null; 
                    break;
                case Secure.Algorithm.Symmetric.DES:
                    _algorithm = DES.Create();
                    break;
                case Secure.Algorithm.Symmetric.TripleDES: 
                    _algorithm = TripleDES.Create(); 
                    break;
                case Secure.Algorithm.Symmetric.AES: 
                    _algorithm = Aes.Create(); 
                    break;
                default:
                    throw new InvalidOperationException("Use invalid symmetric algorithm");
            }

            if (_algorithm != null)
            {
                _algorithm.Key = key;
            }
        }

        /// <summary>
        /// Encrypt data
        /// </summary>
        /// <param name="data">Data to be encrypted</param>
        /// <param name="iv">Initial vector</param>
        /// <returns>Encrypted data</returns>
        public byte[] Encrypt(byte[] data, byte[] iv)
        {
            if (_algorithm == null)
            {
                return data;
            }

            return _algorithm.EncryptCbc(data, iv, paddingMode: PaddingMode.Zeros);
        }

        /// <summary>
        /// Decrypt data
        /// </summary>
        /// <param name="data">Data to be decrypted</param>
        /// <param name="iv">Initial vector</param>
        /// <returns>Decrypted data</returns>
        public byte[] Decrypt(byte[] data, byte[] iv)
        {
            if (_algorithm == null)
            {
                return data;
            }

            return _algorithm.DecryptCbc(data, iv, paddingMode: PaddingMode.Zeros);
        }

        /// <summary>
        /// Return symmetric key size for using algorithm
        /// </summary>
        /// <param name="algorithm">Symmetric algorithm to use</param>
        /// <returns></returns>
        public static int KeySize(Algorithm.Symmetric algorithm)
        {
            switch (algorithm)
            {
                case Secure.Algorithm.Symmetric.None: 
                    return 0;
                case Secure.Algorithm.Symmetric.DES:
                    return 8;
                case Secure.Algorithm.Symmetric.TripleDES:
                    return 24;
                case Secure.Algorithm.Symmetric.AES:
                    return 32;
                default:
                    throw new InvalidOperationException("Use invalid symmetric algorithm");
            }
        }

        /// <summary>
        /// Return symmetric block size for using algorithm
        /// </summary>
        /// <param name="algorithm">Symmetric algorithm to use</param>
        /// <returns></returns>
        public static int BlockSize(Algorithm.Symmetric algorithm)
        {
            switch (algorithm)
            {
                case Secure.Algorithm.Symmetric.None:
                    return 0;
                case Secure.Algorithm.Symmetric.DES:
                    return 8;
                case Secure.Algorithm.Symmetric.TripleDES:
                    return 8;
                case Secure.Algorithm.Symmetric.AES:
                    return 16;
                default:
                    throw new InvalidOperationException("Use invalid symmetric algorithm");
            }
        }
    }
}
