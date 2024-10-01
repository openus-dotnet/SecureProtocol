using Openus.SecureProtocol.Key.Session;
using Openus.SecureProtocol.Secure.Algorithm;
using Openus.SecureProtocol.Secure.Wrapper;
using System.Net;
using System.Security.Cryptography;

namespace Openus.SecureProtocol.Transport
{
    /// <summary>
    /// Abstract base transport type
    /// </summary>
    public abstract class BaseTransport
    {
        /// <summary>
        /// Get local IP end point
        /// </summary>
        public abstract IPEndPoint LocalEP { get; }

        /// <summary>
        /// Keyset wrapped for reuse in UDP, etc., but key cannot be see user
        /// </summary>
        public KeySet SessionKeySet { get => new KeySet(SymmetricKey, HmacKey, AlgorithmSet); }

        /// <summary>
        /// The symmetric key used to communicate with this server
        /// </summary>
        internal byte[] SymmetricKey { get; private set; }
        /// <summary>
        /// The HMAC key used to communicate with this server
        /// </summary>
        internal byte[] HmacKey { get; private set; }
        /// <summary>
        /// Symmetric algorithm supporter
        /// </summary>
        internal Symmetric SymmetricWrapper { get; private set; }
        /// <summary>
        /// Algorithm set to use
        /// </summary>
        internal Set AlgorithmSet { get; private set; }
        /// <summary>
        /// Nonce for preventing retransmission attacks
        /// </summary>
        protected uint _recvNonce;
        /// <summary>
        /// Nonce for preventing retransmission attacks
        /// </summary>
        protected uint _sendNonce;

        /// <summary>
        /// Base transport constructor
        /// </summary>
        /// <param name="set">Algorithm set to use</param>
        /// <param name="symmetricKey">Symmetric key to use</param>
        /// <param name="hmacKey">HMAC key to use</param>
        protected BaseTransport(Set set, byte[] symmetricKey, byte[] hmacKey)
        {
            SymmetricWrapper = new Symmetric(symmetricKey, set.Symmetric);
            AlgorithmSet = set;
            SymmetricKey = symmetricKey;
            HmacKey = hmacKey;
        }

        /// <summary>
        /// Generate symmetric session key and HMAC key
        /// </summary>
        /// <param name="set">Algorithm set to use</param>
        /// <returns>(Symmetric key, HMAC key)</returns>
        protected static (byte[], byte[]) GenerateKeySet(Set set)
        {
            byte[] symmetricKey = new byte[Symmetric.KeySize(set.Symmetric)];
            byte[] hmacKey = new byte[Hash.HmacKeySize(set.Hash)];

            RandomNumberGenerator.Fill(symmetricKey);
            RandomNumberGenerator.Fill(hmacKey);

            return (symmetricKey, hmacKey);
        }

        /// <summary>
        /// Close the client
        /// </summary>
        public abstract void Close();
    }
}
