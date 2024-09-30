using Openus.SecSess.Secure.Algorithm;
using System.Security.Cryptography;

namespace Openus.SecSess.Secure.Wrapper
{
    /// <summary>
    /// Hash support wrapper
    /// </summary>
    internal class Hash
    {
        /// <summary>
        /// Hash data using selected hash algorithm
        /// </summary>
        /// <param name="algorithm">Hash algorithm to use</param>
        /// <param name="data">Data to hash</param>
        /// <returns></returns>
        public static byte[] HashData(HashType algorithm, byte[] data)
        {
            switch (algorithm)
            {
                case HashType.SHA1: return SHA1.HashData(data);
                case HashType.SHA256: return SHA256.HashData(data);
                case HashType.SHA384: return SHA384.HashData(data);
                case HashType.SHA512: return SHA512.HashData(data);
                case HashType.SHA3_256: return SHA3_256.HashData(data);
                case HashType.SHA3_384: return SHA3_384.HashData(data);
                case HashType.SHA3_512: return SHA3_512.HashData(data);
                default: return data;
            }
        }

        /// <summary>
        /// HMAC Hash data using selected hash algorithm
        /// </summary>
        /// <param name="algorithm">HMAC algorithm to use</param>
        /// <param name="key">Key for HMAC</param>
        /// <param name="data">Data to hash</param>
        /// <returns></returns>
        public static byte[] HmacData(HashType algorithm, byte[] key, byte[] data)
        {
            switch (algorithm)
            {
                case HashType.SHA1: return HMACSHA1.HashData(key, data);
                case HashType.SHA256: return HMACSHA256.HashData(key, data);
                case HashType.SHA384: return HMACSHA384.HashData(key, data);
                case HashType.SHA512: return HMACSHA512.HashData(key, data);
                case HashType.SHA3_256: return HMACSHA3_256.HashData(key, data);
                case HashType.SHA3_384: return HMACSHA3_384.HashData(key, data);
                case HashType.SHA3_512: return HMACSHA3_512.HashData(key, data);
                default: return data;
            }
        }

        /// <summary>
        /// Return hashed data size selected hash algorithm
        /// </summary>
        /// <param name="algorithm">Hash algorithm to use</param>
        /// <returns></returns>
        public static int HashDataSize(HashType algorithm)
        {
            switch (algorithm)
            {
                case HashType.SHA1: return 20;
                case HashType.SHA256: return 32;
                case HashType.SHA384: return 48;
                case HashType.SHA512: return 64;
                case HashType.SHA3_256: return 32;
                case HashType.SHA3_384: return 48;
                case HashType.SHA3_512: return 64;
                default: return -1;
            }
        }

        /// <summary>
        /// Return HMAC key size selected hash algorithm
        /// </summary>
        /// <param name="algorithm">Hash algorithm to use</param>
        /// <returns></returns>
        public static int HmacKeySize(HashType algorithm)
        {
            switch (algorithm)
            {
                case HashType.SHA1: return 64;
                case HashType.SHA256: return 64;
                case HashType.SHA384: return 128;
                case HashType.SHA512: return 128;
                case HashType.SHA3_256: return 136;
                case HashType.SHA3_384: return 104;
                case HashType.SHA3_512: return 72;
                default: return 0;
            }
        }
    }
}
