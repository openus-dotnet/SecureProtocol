using SecSess.Interface.Tcp;
using SecSess.Key;
using SecSess.Secure.Wrapper;
using System.Net;
using System.Net.Sockets;

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
            /// The symmetric key used to communicate with this client
            /// </summary>
            public byte[] SymmetricKey { get; private set; }
            /// <summary>
            /// The HMAC key used to communicate with this client
            /// </summary>
            public byte[] HMacKey { get; private set; }

            /// <summary>
            /// Client that actually works
            /// </summary>
            internal TcpClient InnerClient { get; set; }
            /// <summary>
            /// Symmetric algorithm supporter
            /// </summary>
            internal Symmetric Symmetric { get; set; }
            /// <summary>
            /// Hash algorithm to use
            /// </summary>
            internal Secure.Algorithm.Hash HashAlgorithm { get; set; }

            /// <summary>
            /// Create a server side client
            /// </summary>
            /// <param name="client">Client that actually works</param>
            /// <param name="symmetricKey">The AES key used to communicate with this client</param>
            /// <param name="hmacKey">The HMAC key used to communicate with this client</param>
            /// <param name="set">Algorithm set to use</param>
            internal Client(TcpClient client, byte[] symmetricKey, byte[] hmacKey, Secure.Algorithm.Set set)
            {
                InnerClient = client;
                SymmetricKey = symmetricKey;
                HMacKey = hmacKey;
                Symmetric = new Symmetric(symmetricKey, set.Symmetric);
                HashAlgorithm = set.Hash;
            }

            /// <summary>
            /// Write packet with secure session
            /// </summary>
            /// <param name="data">Data that write to client</param>
            public void Write(byte[] data)
            {
                IStream.InternalWrite(data, Symmetric, HMacKey, HashAlgorithm, InnerClient);
            }

            /// <summary>
            /// Read packet with secure session
            /// </summary>
            /// <returns>Data that read from client</returns>
            public byte[] Read()
            {
                return IStream.InternalRead(Symmetric, HMacKey, HashAlgorithm, InnerClient);
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
        private Server(TcpListener listener, AsymmetricKeyBase? parameters, Secure.Algorithm.Set set) 
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
        public static Server Create(IPEndPoint endPoint, PrivateKey? key, Secure.Algorithm.Set set)
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

            if (_asymmetric.AsymmetricAlgorithm != null && _set.Symmetric != Secure.Algorithm.Symmetric.None)
            {
                byte[] buffer = new byte[256];

                int s = 0;
                while (s < buffer.Length)
                    s += client.GetStream().Read(buffer, s, buffer.Length - s);

                byte[] concat = _asymmetric.Decrypt(buffer);
                byte[] symmetricKey = concat[0..Symmetric.KeySize(_set.Symmetric)];
                byte[] hmacKey = concat[Symmetric.KeySize(_set.Symmetric)..(Symmetric.KeySize(_set.Symmetric) + Hash.HMacKeySize(_set.Hash))];

                Client result = new Client(client, symmetricKey, hmacKey, _set);
                _clients.Add(result);

                while (client.GetStream().CanWrite == false) ;

                result.Write(Hash.HashData(_set.Hash, concat));

                return result;
            }
            else if (_asymmetric.AsymmetricAlgorithm == null && _set.Symmetric == Secure.Algorithm.Symmetric.None)
            {
                Client result = new Client(client, Array.Empty<byte>(), Array.Empty<byte>(), _set);
                _clients.Add(result);

                return result;
            }
            else
            {
                throw new InvalidOperationException("Invalid combination between asymmetric to symmetric algorithm.");
            }
        }
    }
}
