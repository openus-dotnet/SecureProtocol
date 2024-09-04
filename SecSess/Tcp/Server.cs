using SecSess.Key;
using SecSess.Util;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace SecSess.Tcp
{
    /// <summary>
    /// TCP server with secure sessions
    /// </summary>
    public class Server
    {
        /// <summary>
        /// Clients accepted by the server side
        /// </summary>
        public class Client
        {
            /// <summary>
            /// Client that actually works
            /// </summary>
            internal TcpClient InnerClient { get; set; }

            /// <summary>
            /// The AES key used to communicate with this client
            /// </summary>
            internal byte[] AESKey { get; set; }

            /// <summary>
            /// Create a server side client
            /// </summary>
            /// <param name="client">Client that actually works</param>
            /// <param name="aesKey">The AES key used to communicate with this client</param>
            internal Client(TcpClient client, byte[] aesKey)
            {
                InnerClient = client;
                AESKey = aesKey;
            }
        }

        /// <summary>
        /// A TCP listener that actually works
        /// </summary>
        private TcpListener _listener;
        /// <summary>
        /// Secure client list
        /// </summary>
        private List<Client> _clients;
        /// <summary>
        /// RSA with private key for server
        /// </summary>
        private RSA _rsa;

        /// <summary>
        /// General constructor for server
        /// </summary>
        /// <param name="listener">A TCP listener that actually works</param>
        /// <param name="parameters">RSA parameters with private values for server</param>
        private Server(TcpListener listener, RSAParameters parameters) 
        {
            _listener = listener;
            _clients = new List<Client>();
            _rsa = RSA.Create(parameters);
        }

        /// <summary>
        /// Create a server where secure sessions are provided
        /// </summary>
        /// <param name="ip">IP string like (X.X.X.X)</param>
        /// <param name="port">Port number</param>
        /// <param name="key">Private key for server</param>
        /// <returns>Server created (not Start())</returns>
        public static Server Create(string ip, int port, PrivateKey key)
        {
            return new Server(new TcpListener(IPEndPoint.Parse($"{ip}:{port}")), key.InnerRSA);
        }
        /// <summary>
        /// Create a server where secure sessions are provided
        /// </summary>
        /// <param name="endPoint">IP string like (X.X.X.X:X)</param>
        /// <param name="key">Private key for server</param>
        /// <returns>Server created (not Start())</returns>
        public static Server Create(string endPoint, PrivateKey key)
        {
            return new Server(new TcpListener(IPEndPoint.Parse(endPoint)), key.InnerRSA);
        }
        /// <summary>
        /// Create a server where secure sessions are provided
        /// </summary>
        /// <param name="address">IP address</param>
        /// <param name="port">Port number</param>
        /// <param name="key">Private key for server</param>
        /// <returns>Server created (not Start())</returns>
        public static Server Create(IPAddress address, int port, PrivateKey key)
        {
            return new Server(new TcpListener(new IPEndPoint(address, port)), key.InnerRSA);
        }
        /// <summary>
        /// Create a server where secure sessions are provided
        /// </summary>
        /// <param name="endPoint">IP end point</param>
        /// <param name="key">Private key for server</param>
        /// <returns>Server created (not Start())</returns>
        public static Server Create(IPEndPoint endPoint, PrivateKey key)
        {
            return new Server(new TcpListener(endPoint), key.InnerRSA);
        }

        /// <summary>
        /// Start TCP listener
        /// </summary>
        public void Start()
        {
            _listener.Start();
        }

        /// <summary>
        /// Stop TCP listener
        /// </summary>
        public void Stop()
        {
            _listener.Stop();
        }

        /// <summary>
        /// Accept a pending connection request
        /// </summary>
        public Client AcceptClient()
        {
            try
            {
                TcpClient client = _listener.AcceptTcpClient();

                byte[] buffer = new byte[512];
                client.GetStream().Read(buffer, 0, 512);

                byte[] data = _rsa.Decrypt(buffer, RSAEncryptionPadding.Pkcs1);

                Client result = new Client(client, data);
                _clients.Add(result);

                client.GetStream().Write(new AESWrapper(data).Encrypt("OK".GetBytes()));

                return result;
            }
            catch
            {
                throw new SecSessRefuesedException();
            }
        }
    }
}
