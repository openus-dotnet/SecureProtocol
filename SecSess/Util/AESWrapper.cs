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
        private byte[] _iv;

        public AESWrapper(byte[] key)
        {
            _aes = Aes.Create();
            _aes.Key = key;
            _iv = new byte[16];
        }

        public byte[] Encrypt(byte[] data)
        {
            return _aes.EncryptCbc(data, _iv, paddingMode: PaddingMode.PKCS7);
        }

        public byte[] Decrypt(byte[] data)
        {
            return _aes.DecryptCbc(data, _iv, paddingMode: PaddingMode.PKCS7);
        }
    }
}
