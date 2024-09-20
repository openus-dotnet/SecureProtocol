using SecSess.Interface;
using SecSess.Key;
using SecSess.Secure;
using SecSess.Util;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace SecSess.Tcp
{
    /// <summary>
    /// TCP client with secure sessions
    /// </summary>
    public class Client : IStream
    {
        /// <summary>
        /// A TCP client that actually works
        /// </summary>
        private TcpClient _client;
        /// <summary>
        /// Asymmetric algorithm set without private key for client
        /// </summary>
        private Asymmetric _asymmetric;
        /// <summary>
        /// IP of the server to which you want to connect
        /// </summary>
        private IPEndPoint _serverPoint;
        /// <summary>
        /// Symmetric algorithm supporter
        /// </summary>
        private Symmetric _symmetric { get; set; }
        /// <summary>
        /// The symmetric key used to communicate with this server
        /// </summary>
        private byte[] _symmetricKey;
        /// <summary>
        /// Algorithm set to use
        /// </summary>
        private Secure.Algorithm.Set _set;

        /// <summary>
        /// Create client
        /// </summary>
        /// <param name="endPoint">IP end point for server</param>
        /// <param name="rsa">Asymmetric key base without private key for client</param>
        /// <param name="set">Algorithm set to use</param>
        private Client(IPEndPoint endPoint, AsymmetricKeyBase rsa, Secure.Algorithm.Set set)
        {
            _client = new TcpClient();
            _serverPoint = endPoint;
            _asymmetric = new Asymmetric(rsa, set.Asymmetric);
            _symmetricKey = new byte[32];
            _symmetric = new Symmetric(_symmetricKey, set.Symmetric);
            _set = set;

            new Random(DateTime.Now.Microsecond).NextBytes(_symmetricKey);
        }

        /// <summary>
        /// Create a client where secure sessions are provided
        /// </summary>
        /// <param name="ip">IP string for server like (X.X.X.X)</param>
        /// <param name="port">Port number for server</param>
        /// <param name="key">Public key for server</param>
        /// <param name="set">Algorithm set to use</param>
        /// <returns>Client created (not Connect())</returns>
        public static Client Create(string ip, int port, PublicKey key, Secure.Algorithm.Set set)
        {
            return new Client(IPEndPoint.Parse($"{ip}:{port}"), key, set);
        }
        /// <summary>
        /// Create a client where secure sessions are provided
        /// </summary>
        /// <param name="endPoint">IP string for server like (X.X.X.X:X)</param>
        /// <param name="key">Public key for server</param>
        /// <param name="set">Algorithm set to use</param>
        /// <returns>Client created (not Connect())</returns>
        public static Client Create(string endPoint, PublicKey key, Secure.Algorithm.Set set)
        {
            return new Client(IPEndPoint.Parse(endPoint), key, set);
        }
        /// <summary>
        /// Create a client where secure sessions are provided
        /// </summary>
        /// <param name="address">IP address for server</param>
        /// <param name="port">Port number for server</param>
        /// <param name="key">Public key for server</param>
        /// <param name="set">Algorithm set to use</param>
        /// <returns>Client created (not Connect())</returns>
        public static Client Create(IPAddress address, int port, PublicKey key, Secure.Algorithm.Set set)
        {
            return new Client(new IPEndPoint(address, port), key, set);
        }
        /// <summary>
        /// Create a client where secure sessions are provided
        /// </summary>
        /// <param name="endPoint">IP end point for server</param>
        /// <param name="key">Public key for server</param>
        /// <param name="set">Algorithm set to use</param>
        /// <returns>Client created (not Connect())</returns>
        public static Client Create(IPEndPoint endPoint, PublicKey key, Secure.Algorithm.Set set)
        {
            return new Client(endPoint, key, set);
        }

        /// <summary>
        /// Connect to a preconfigured server
        /// </summary>
        public void Connect()
        {
            _client.Connect(_serverPoint);

            while (CanUseStream() == false) ;

            if (_asymmetric.AsymmetricAlgorithm != null)
            {
                byte[] symmetricKey = _asymmetric.AsymmetricAlgorithm.Encrypt(_symmetricKey, RSAEncryptionPadding.Pkcs1);
                _client.GetStream().Write(symmetricKey, 0, symmetricKey.Length);

                byte[] buffer = new byte[16];

                int s = 0;
                while (s < buffer.Length)
                    s += _client.GetStream().Read(buffer, s, buffer.Length - s);

                string res = new Symmetric(_symmetricKey, _set.Symmetric).Decrypt(buffer, new byte[16]).GetString();

                _symmetric = new Symmetric(_symmetricKey, _set.Symmetric);

                if (res.StartsWith("OK") == false)
                {
                    throw new SecSessRefuesedException();
                }
            }
        }

        /// <summary>
        /// Close the TCP client
        /// </summary>
        public void Close()
        {
            _client.Close();
        }

        /// <summary>
        /// Write packet with secure session
        /// </summary>
        /// <param name="data">Data that write to server</param>
        public void Write(byte[] data)
        {
            IStream.InternalWrite(data, _symmetric, _client);
        }

        /// <summary>
        /// Read packet with secure session
        /// </summary>
        /// <returns>Data that read from server</returns>
        public byte[] Read()
        {
            return IStream.InternalRead(_symmetric, _client);
        }

        /// <summary>
        /// Determine if tcp client state is available
        /// </summary>
        /// <param name="type">The type of client state to judge</param>
        /// <returns></returns>
        public bool CanUseStream(StreamType type = StreamType.All)
        {
            return (type.HasFlag(StreamType.Connect) == true ? _client.Connected : true)
                && (type.HasFlag(StreamType.Read) == true ? _client.GetStream().CanRead : true)
                && (type.HasFlag(StreamType.Write) == true ? _client.GetStream().CanWrite : true);
        }

        /// <summary>
        /// Flushes data from stream
        /// </summary>
        public void FlushStream()
        {
            _client.GetStream().Flush();
        }
    }
}
