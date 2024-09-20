using SecSess.Interface;
using SecSess.Key;
using SecSess.Secure.Wrapper;
using SecSess.Util;
using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;
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
        /// Symmetric algorithm supporter
        /// </summary>
        private Symmetric _symmetric { get; set; }
        /// <summary>
        /// The symmetric key used to communicate with this server
        /// </summary>
        private byte[] _symmetricKey;
        /// <summary>
        /// The HMAC key used to communicate with this server
        /// </summary>
        private byte[] _hmacKey;
        /// <summary>
        /// Algorithm set to use
        /// </summary>
        private Secure.Algorithm.Set _set;

        /// <summary>
        /// Create client
        /// </summary>
        /// <param name="parameter">Asymmetric key base without private key for client</param>
        /// <param name="set">Algorithm set to use</param>
        private Client(AsymmetricKeyBase? parameter, Secure.Algorithm.Set set)
        {
            _symmetricKey = new byte[Symmetric.KeySize(set.Symmetric)];
            _hmacKey = new byte[Hash.HMacKeySize(set.Hash)];

            RandomNumberGenerator.Fill(_symmetricKey);
            RandomNumberGenerator.Fill(_hmacKey);

            _client = new TcpClient();
            _asymmetric = new Asymmetric(parameter, set.Asymmetric);
            _symmetric = new Symmetric(_symmetricKey, set.Symmetric);
            _set = set;
        }

        /// <summary>
        /// Create a client where secure sessions are provided
        /// </summary>
        /// <param name="key">Public key for server</param>
        /// <param name="set">Algorithm set to use</param>
        /// <returns>Client created (not Connect())</returns>
        public static Client Create(PublicKey? key, Secure.Algorithm.Set set)
        {
            return new Client(key, set);
        }

        /// <summary>
        /// Connect to a preconfigured server
        /// <param name="serverEP"/>Server IP end point</param>
        /// <param name="retry">Maximum retry to connect</param>
        /// </summary>
        public void Connect(IPEndPoint serverEP, int retry = 0)
        {
            if (retry == 0)
            {
                _client.Connect(serverEP);
            }
            else
            {
                for (int i = 0; i < retry; i++)
                {
                    try
                    {
                        _client.Connect(serverEP);

                        break;
                    }
                    catch (SocketException)
                    {
                        continue;
                    }
                }
            }

            while (CanUseStream() == false);

            if (_asymmetric.AsymmetricAlgorithm != null && _symmetric.Algorithm != Secure.Algorithm.Symmetric.None)
            {
                byte[] buffer = new byte[_symmetricKey.Length + _hmacKey.Length];
                
                Buffer.BlockCopy(_symmetricKey, 0, buffer, 0, _symmetricKey.Length);
                Buffer.BlockCopy(_hmacKey, 0, buffer, _symmetricKey.Length, _hmacKey.Length);

                byte[] enc = _asymmetric.Encrypt(buffer);
                _client.GetStream().Write(enc, 0, enc.Length);

                byte[] response = Read();
                byte[] compare = Hash.HashData(_set.Hash, buffer);

                _symmetric = new Symmetric(_symmetricKey, _set.Symmetric);

                if (compare.SequenceEqual(response) == false)
                {
                    throw new AuthenticationException("Failed to create a secure session.");
                }
            }
            else if (_asymmetric.AsymmetricAlgorithm == null && _symmetric.Algorithm == Secure.Algorithm.Symmetric.None)
            {

            }
            else
            {
                 throw new InvalidOperationException("Invalid combination between asymmetric to symmetric algorithm.");
            }
        }

        /// <summary>
        /// Close the TCP client
        /// </summary>
        public void Close()
        {
            _client.Close();
            _client.Dispose();
        }

        /// <summary>
        /// Write packet with secure session
        /// </summary>
        /// <param name="data">Data that write to server</param>
        public void Write(byte[] data)
        {
            IStream.InternalWrite(data, _symmetric, _hmacKey, _set.Hash, _client);
        }

        /// <summary>
        /// Read packet with secure session
        /// </summary>
        /// <returns>Data that read from server</returns>
        public byte[] Read()
        {
            return IStream.InternalRead(_symmetric, _hmacKey, _set.Hash, _client);
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
