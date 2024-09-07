using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SecSess.Secure
{
    /// <summary>
    /// Custom AES Wrapper
    /// </summary>
    internal class AESWrapper
    {
        /// <summary>
        /// AES that actually works.
        /// </summary>
        private Aes _aes;

        /// <summary>
        /// Create an AES wrapper with the given key
        /// </summary>
        /// <param name="key">AES key</param>
        public AESWrapper(byte[] key)
        {
            _aes = Aes.Create();
            _aes.Key = key;
        }

        /// <summary>
        /// Encrypt data
        /// </summary>
        /// <param name="data">Data to be encrypted</param>
        /// <param name="iv">Initial vector</param>
        /// <returns>Encrypted data</returns>
        public byte[] Encrypt(byte[] data, byte[] iv)
        {
            return _aes.EncryptCbc(data, iv, paddingMode: PaddingMode.Zeros);
        }

        /// <summary>
        /// Decrypt data
        /// </summary>
        /// <param name="data">Data to be decrypted</param>
        /// <param name="iv">Initial vector</param>
        /// <returns>Decrypted data</returns>
        public byte[] Decrypt(byte[] data, byte[] iv)
        {
            return _aes.DecryptCbc(data, iv, paddingMode: PaddingMode.Zeros);
        }
    }
}
