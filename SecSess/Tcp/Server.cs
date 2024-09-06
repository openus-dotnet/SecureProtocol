using SecSess.Key;
using SecSess.Util;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using static SecSess.Tcp.Server;

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
            /// AES support wrapper
            /// </summary>
            internal AESWrapper AESWrapper { get; set; }
            /// <summary>
            /// Initial vector for sent AES packet
            /// </summary>
            private byte[] _sentIV;
            /// <summary>
            /// Initial vector for received AES packet
            /// </summary>
            private byte[] _receivedIV;

            /// <summary>
            /// Create a server side client
            /// </summary>
            /// <param name="client">Client that actually works</param>
            /// <param name="aesKey">The AES key used to communicate with this client</param>
            internal Client(TcpClient client, byte[] aesKey)
            {
                InnerClient = client;
                AESKey = aesKey;
                AESWrapper = new AESWrapper(aesKey);

                _sentIV = aesKey[16..32];
                _receivedIV = aesKey[0..16];
            }

            /// <summary>
            /// Write packet with secure session
            /// </summary>
            /// <param name="data">Data that write to client</param>
            public void Write(byte[] data)
            {
                byte[] lenBit = BitConverter.GetBytes(data.Length);
                byte[] msg = new byte[data.Length + 4];

                for (int i = 0; i < 4; i++)
                {
                    msg[i] = lenBit[i];
                }
                for (int i = 0; i < data.Length; i++)
                {
                    msg[i + 4] = data[i];
                }

                byte[] enc = AESWrapper.Encrypt(msg, _sentIV);
                InnerClient.GetStream().Write(enc, 0, enc.Length);

                _sentIV = enc[0..16];
            }

            /// <summary>
            /// Read packet with secure session
            /// </summary>
            /// <returns>Data that read from client</returns>
            public byte[] Read()
            {
                byte[] enc = new byte[16];
                InnerClient.GetStream().Read(enc, 0, enc.Length);

                byte[] msg1 = AESWrapper.Decrypt(enc, _receivedIV);
                _receivedIV = enc[0..16];

                int len = BitConverter.ToInt32(msg1[0..4]);
                int blockCount = (len + 4) / 16 + ((len + 4) % 16 == 0 ? 0 : 1);

                byte[] buffer = new byte[(blockCount - 1) * 16];

                if (buffer.Length != 0)
                {
                    InnerClient.GetStream().Read(buffer, 0, buffer.Length);
                    byte[] msg2 = AESWrapper.Decrypt(buffer, _receivedIV);

                    byte[] data = new byte[len];

                    int offset = 0;

                    for (; offset < 12; offset++)
                    {
                        data[offset] = msg1[offset + 4];
                    }
                    for (; offset < data.Length; offset++)
                    {
                        data[offset] = msg2[offset - 12];
                    }

                    return data;
                }
                else
                {
                    return msg1[4..(len + 4)];
                }
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
            TcpClient client = _listener.AcceptTcpClient();

            while (client.Connected == false || client.GetStream().CanRead == false) ;

            byte[] buffer = new byte[512];
            client.GetStream().Read(buffer, 0, buffer.Length);

            byte[] aesKey = _rsa.Decrypt(buffer, RSAEncryptionPadding.Pkcs1);

            Client result = new Client(client, aesKey);
            _clients.Add(result);

            while (client.GetStream().CanWrite == false) ;

            client.GetStream().Write(result.AESWrapper.Encrypt("OK".GetBytes(), new byte[16]), 0, 16);

            return result;
        }
    }
}
