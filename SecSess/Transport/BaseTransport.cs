using Openus.Net.SecSess.Secure.Algorithm;
using Openus.Net.SecSess.Secure.Wrapper;
using System.Net;
using System.Net.Sockets;

namespace Openus.Net.SecSess.Transport
{
    public abstract class BaseTransport
    {
        /// <summary>
        /// Get local IP end point
        /// </summary>
        public abstract IPEndPoint LocalEP { get; }
        /// <summary>
        /// Get remote IP end point
        /// </summary>
        public abstract IPEndPoint RemoteEP { get; }

        /// <summary>
        /// The symmetric key used to communicate with this server
        /// </summary>
        public byte[] SymmetricKey { get; private set; }
        /// <summary>
        /// The HMAC key used to communicate with this server
        /// </summary>
        public byte[] HMacKey { get; private set; }

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
        protected int _recvNonce;
        /// <summary>
        /// Nonce for preventing retransmission attacks
        /// </summary>
        protected int _sendNonce;

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
            HMacKey = hmacKey;
        }
    }
}
