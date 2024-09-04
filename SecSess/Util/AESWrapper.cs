using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SecSess.Util
{
    /// <summary>
    /// Custom AES Wrapper
    /// </summary>
    internal class AESWrapper
    {
        private Aes _aes;

        public AESWrapper(byte[] key)
        {
            _aes = Aes.Create();
            _aes.Key = key;
        }

        public byte[] Encrypt(byte[] data, byte[] iv)
        {
            return _aes.EncryptCbc(data, iv, paddingMode: PaddingMode.Zeros);
        }

        public byte[] Decrypt(byte[] data, byte[] iv)
        {
            return _aes.DecryptCbc(data, iv, paddingMode: PaddingMode.Zeros);
        }
    }
}
