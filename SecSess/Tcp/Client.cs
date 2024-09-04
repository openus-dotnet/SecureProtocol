using SecSess.Key;
using SecSess.Util;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace SecSess.Tcp
{
    /// <summary>
    /// TCP client with secure sessions
    /// </summary>
    public class Client
    {
        /// <summary>
        /// A TCP client that actually works
        /// </summary>
        private TcpClient _client;
        /// <summary>
        /// RSA without private key for server
        /// </summary>
        private RSA _rsa;
        /// <summary>
        /// IP of the server to which you want to connect
        /// </summary>
        private IPEndPoint _serverPoint;

        /// <summary>
        /// The AES key used to communicate with this server
        /// </summary>
        private byte[] _aesKey;

        private Client(IPEndPoint endPoint, RSAParameters rsa)
        {
            _client = new TcpClient();
            _serverPoint = endPoint;
            _rsa = RSA.Create(rsa);
            _aesKey = new byte[32];

            new Random(DateTime.Now.Microsecond).NextBytes(_aesKey);
        }

        /// <summary>
        /// Create a client where secure sessions are provided
        /// </summary>
        /// <param name="ip">IP string for server like (X.X.X.X)</param>
        /// <param name="port">Port number for server</param>
        /// <param name="key">Public key for server</param>
        /// <returns>Client created (not Connect())</returns>
        public static Client Create(string ip, int port, PublicKey key)
        {
            return new Client(IPEndPoint.Parse($"{ip}:{port}"), key.InnerRSA);
        }
        /// <summary>
        /// Create a client where secure sessions are provided
        /// </summary>
        /// <param name="endPoint">IP string for server like (X.X.X.X:X)</param>
        /// <param name="key">Public key for server</param>
        /// <returns>Client created (not Connect())</returns>
        public static Client Create(string endPoint, PublicKey key)
        {
            return new Client(IPEndPoint.Parse(endPoint), key.InnerRSA);
        }
        /// <summary>
        /// Create a client where secure sessions are provided
        /// </summary>
        /// <param name="address">IP address for server</param>
        /// <param name="port">Port number for server</param>
        /// <param name="key">Public key for server</param>
        /// <returns>Client created (not Connect())</returns>
        public static Client Create(IPAddress address, int port, PublicKey key)
        {
            return new Client(new IPEndPoint(address, port), key.InnerRSA);
        }
        /// <summary>
        /// Create a client where secure sessions are provided
        /// </summary>
        /// <param name="endPoint">IP end point for server</param>
        /// <param name="key">Public key for server</param>
        /// <returns>Client created (not Connect())</returns>
        public static Client Create(IPEndPoint endPoint, PublicKey key)
        {
            return new Client(endPoint, key.InnerRSA);
        }

        /// <summary>
        /// Connect to a preconfigured server
        /// </summary>
        public void Connect()
        {
            try
            {
                _client.Connect(_serverPoint);

                byte[] data = _rsa.Encrypt(_aesKey, RSAEncryptionPadding.Pkcs1);
                _client.GetStream().Write(data);

                _client.GetStream().Read(data = new byte[16], 0, 16);
                string res = new AESWrapper(_aesKey).Decrypt(data).GetString();

                if (res != "OK")
                {
                    throw new Exception();
                }
            }
            catch
            {
                throw new SecSessRefuesedException();
            }
        }
    }
}
