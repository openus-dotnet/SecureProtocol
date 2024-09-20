using SecSess.Interface;
using SecSess.Key;
using SecSess.Secure;
using SecSess.Util;
using System;
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
        public class Client : IStream
        {
            /// <summary>
            /// Client that actually works
            /// </summary>
            internal TcpClient InnerClient { get; set; }
            /// <summary>
            /// The symmetric key used to communicate with this client
            /// </summary>
            internal byte[] SymmetricKey { get; set; }
            /// <summary>
            /// Symmetric algorithm supporter
            /// </summary>
            internal Symmetric Symmetric { get; set; }

            /// <summary>
            /// Create a server side client
            /// </summary>
            /// <param name="client">Client that actually works</param>
            /// <param name="symmetricKey">The AES key used to communicate with this client</param>
            /// <param name="set">Algorithm set to use</param>
            internal Client(TcpClient client, byte[] symmetricKey, Secure.Algorithm.Set set)
            {
                InnerClient = client;
                SymmetricKey = symmetricKey;
                Symmetric = new Symmetric(symmetricKey, set.Symmetric);
            }

            /// <summary>
            /// Write packet with secure session
            /// </summary>
            /// <param name="data">Data that write to client</param>
            public void Write(byte[] data)
            {
                IStream.InternalWrite(data, Symmetric, InnerClient);
            }

            /// <summary>
            /// Read packet with secure session
            /// </summary>
            /// <returns>Data that read from client</returns>
            public byte[] Read()
            {
                return IStream.InternalRead(Symmetric, InnerClient);
            }

            /// <summary>
            /// Determine if tcp client state is available
            /// </summary>
            /// <param name="type">The type of client state to judge</param>
            /// <returns></returns>
            public bool CanUseStream(StreamType type = StreamType.All)
            {
                return (type.HasFlag(StreamType.Connect) == true ? InnerClient.Connected : true)
                    && (type.HasFlag(StreamType.Read) == true ? InnerClient.GetStream().CanRead : true)
                    && (type.HasFlag(StreamType.Write) == true ? InnerClient.GetStream().CanWrite : true);
            }

            /// <summary>
            /// Flushes data from stream
            /// </summary>
            public void FlushStream()
            {
                InnerClient.GetStream().Flush();
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
        /// Asymmetric algorithm with private key for server
        /// </summary>
        private Asymmetric _asymmetric;
        /// <summary>
        /// Algorithm set to use
        /// </summary>
        private Secure.Algorithm.Set _set;

        /// <summary>
        /// General constructor for server
        /// </summary>
        /// <param name="listener">A TCP listener that actually works</param>
        /// <param name="parameters">Asymmetric key base with private key for server</param>
        /// <param name="set">Algorithm set to use</param>
        private Server(TcpListener listener, AsymmetricKeyBase parameters, Secure.Algorithm.Set set) 
        {
            _listener = listener;
            _clients = new List<Client>();
            _asymmetric = new Asymmetric(parameters, set.Asymmetric);
            _set = set;
        }

        /// <summary>
        /// Create a server where secure sessions are provided
        /// </summary>
        /// <param name="endPoint">IP end point</param>
        /// <param name="key">Private key for server</param>
        /// <param name="set">Algorithm set to use</param>
        /// <returns>Server created (not Start())</returns>
        public static Server Create(IPEndPoint endPoint, PrivateKey key, Secure.Algorithm.Set set)
        {
            return new Server(new TcpListener(endPoint), key, set);
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
            _listener.Dispose();
        }

        /// <summary>
        /// Accept a pending connection request
        /// </summary>
        public Client AcceptClient()
        {
            TcpClient client = _listener.AcceptTcpClient();

            while (client.Connected == false || client.GetStream().CanRead == false) ;

            if (_asymmetric.AsymmetricAlgorithm != null)
            {
                byte[] buffer = new byte[256];

                int s = 0;
                while (s < buffer.Length)
                    s += client.GetStream().Read(buffer, s, buffer.Length - s);

                byte[] symmetricKey = _asymmetric.AsymmetricAlgorithm.Decrypt(buffer, RSAEncryptionPadding.Pkcs1);

                Client result = new Client(client, symmetricKey, _set);
                _clients.Add(result);

                while (client.GetStream().CanWrite == false) ;

                buffer = result.Symmetric.Encrypt("OK".GetBytes(), new byte[Symmetric.BlockSize(_set.Symmetric)]);
                client.GetStream().Write(buffer, 0, buffer.Length);

                return result;
            }
            else
            {
                byte[] symmetricKey = new byte[Symmetric.KeySize(_set.Symmetric)];

                int s = 0;
                while (s < symmetricKey.Length)
                    s += client.GetStream().Read(symmetricKey, s, symmetricKey.Length - s);

                Client result = new Client(client, symmetricKey, _set);
                _clients.Add(result);

                while (client.GetStream().CanWrite == false) ;

                byte[] buffer = result.Symmetric.Encrypt("OK".GetBytes(), new byte[Symmetric.BlockSize(_set.Symmetric)]);
                client.GetStream().Write(buffer, 0, buffer.Length);

                return result;
            }
        }
    }
}
