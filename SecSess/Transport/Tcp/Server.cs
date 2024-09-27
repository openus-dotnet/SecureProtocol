using Openus.Net.SecSess.Key.Asymmetric;
using Openus.Net.SecSess.Secure.Algorithm;
using Openus.Net.SecSess.Secure.Wrapper;
using System.Net.Sockets;
using System.Net;
using Openus.Net.SecSess.Transport.Option;

namespace Openus.Net.SecSess.Transport.Tcp
{
    /// <summary>
    /// TCP server with secure sessions
    /// </summary>
    public class Server
    {
        /// <summary>
        /// Clients accepted by the server side
        /// </summary>
        public class Client : BaseTCP
        {
            /// <summary>
            /// Create a server side client
            /// </summary>
            /// <param name="client">Client that actually works</param>
            /// <param name="symmetricKey">The AES key used to communicate with this client</param>
            /// <param name="hmacKey">The HMAC key used to communicate with this client</param>
            /// <param name="set">Algorithm set to use</param>
            internal Client(TcpClient client, byte[] symmetricKey, byte[] hmacKey, Set set)
                : base(client, set, symmetricKey, hmacKey) { }
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
        private Set _set;

        /// <summary>
        /// General constructor for server
        /// </summary>
        /// <param name="listener">A TCP listener that actually works</param>
        /// <param name="parameters">Asymmetric key base with private key for server</param>
        /// <param name="set">Algorithm set to use</param>
        private Server(TcpListener listener, BaseAsymmetricKey? parameters, Set set)
        {
            _listener = listener;
            _clients = new List<Client>();
            _asymmetric = new Asymmetric(parameters, set.Asymmetric);
            _set = set;
        }

        /// <summary>
        /// Create a server without secure session
        /// </summary>
        /// <param name="endPoint"></param>
        /// <returns>Server created (already not Start())</returns>
        public static Server Craete(IPEndPoint endPoint)
        {
            return new Server(new TcpListener(endPoint), null, Set.NoneSet);
        }

        /// <summary>
        /// Create a server where secure session is provided
        /// </summary>
        /// <param name="endPoint">IP end point</param>
        /// <param name="key">Private key for server</param>
        /// <param name="set">Algorithm set to use</param>
        /// <returns>Server created (already not Start())</returns>
        public static Server Create(IPEndPoint endPoint, PrivateKey? key, Set set)
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
        /// <param name="type">How to handle when error</param>
        public Client? AcceptClient(HandlingType type = HandlingType.Ecexption)
        {
            TcpClient client = _listener.AcceptTcpClient();

            while (client.Connected == false || client.GetStream().CanRead == false) ;

            if (_set.Symmetric != SymmetricType.None)
            {
                byte[] buffer = new byte[Asymmetric.BlockSize(_set.Asymmetric)];

                int s = 0;
                while (s < buffer.Length)
                    s += client.GetStream().Read(buffer, s, buffer.Length - s);

                byte[]? concat = _asymmetric.Decrypt(buffer);

                if (concat == null) 
                {
                    switch (type)
                    {
                        case HandlingType.Ecexption:
                            throw new InvalidDataException("Error in asymmetric decrypt.");
                        case HandlingType.EmptyReturn: 
                            return null;
                        default:
                            throw new InvalidOperationException("Invalid Handling type.");
                    }
                }

                byte[] symmetricKey = concat[0..Symmetric.KeySize(_set.Symmetric)];
                byte[] hmacKey = concat[Symmetric.KeySize(_set.Symmetric)..(Symmetric.KeySize(_set.Symmetric) + Hash.HMacKeySize(_set.Hash))];

                Client result = new Client(client, symmetricKey, hmacKey, _set);
                _clients.Add(result);

                while (client.GetStream().CanWrite == false) ;

                result.Write(Hash.HashData(_set.Hash, concat[0..(Symmetric.KeySize(_set.Symmetric) + Hash.HMacKeySize(_set.Hash))]));

                return result;
            }
            else if (_set.Symmetric == SymmetricType.None)
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


        /// <summary>
        /// Accept a pending connection request
        /// </summary>
        /// <param name="type">How to handle when error</param>
        public async Task<Client?> AcceptClientAsync(HandlingType type = HandlingType.Ecexption)
        {
            return await Task.Run(() => AcceptClient(type));
        }
    }
}
