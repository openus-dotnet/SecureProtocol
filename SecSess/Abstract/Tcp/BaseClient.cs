using Openus.Net.SecSess.Secure.Algorithm;
using Openus.Net.SecSess.Secure.Wrapper;
using System.Net;
using System.Net.Sockets;

namespace Openus.Net.SecSess.Abstract.Tcp
{
    /// <summary>
    /// The abstract base class for TCP client
    /// </summary>
    public abstract class BaseClient
    {
        /// <summary>
        /// Get local IP end point
        /// </summary>
        public IPEndPoint LocalEP { get => (ActuallyClient.Client.LocalEndPoint as IPEndPoint)!; }
        /// <summary>
        /// Get remote IP end point
        /// </summary>
        public IPEndPoint RemoteEP { get => (ActuallyClient.Client.RemoteEndPoint as IPEndPoint)!; }

        /// <summary>
        /// The symmetric key used to communicate with this server
        /// </summary>
        public byte[] SymmetricKey { get; private set; }
        /// <summary>
        /// The HMAC key used to communicate with this server
        /// </summary>
        public byte[] HMacKey { get; private set; }

        /// <summary>
        /// A TCP client that actually works
        /// </summary>
        public TcpClient ActuallyClient { get; private set; }
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
        protected int _nonce;

        /// <summary>
        /// Base client constructor
        /// </summary>
        /// <param name="client">TCP client that actually works</param>
        /// <param name="set">Algorithm set to use</param>
        /// <param name="symmetricKey">Symmetric key to use</param>
        /// <param name="hmacKey">HMAC key to use</param>
        internal BaseClient(TcpClient client, Set set, byte[] symmetricKey, byte[] hmacKey)
        {
            ActuallyClient = client;
            SymmetricWrapper = new Symmetric(symmetricKey, set.Symmetric);
            AlgorithmSet = set;
            SymmetricKey = symmetricKey;
            HMacKey = hmacKey;
        }
    }
}
