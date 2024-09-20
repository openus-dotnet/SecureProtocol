using SecSess.Interface;
using SecSess.Key;
using SecSess.Secure;
using SecSess.Util;
using System;
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
        /// <param name="rsa">Asymmetric key base without private key for client</param>
        /// <param name="set">Algorithm set to use</param>
        private Client(AsymmetricKeyBase rsa, Secure.Algorithm.Set set)
        {
            _symmetricKey = new byte[Symmetric.KeySize(set.Symmetric)];
            new Random(DateTime.Now.Microsecond).NextBytes(_symmetricKey);

            _client = new TcpClient();
            _asymmetric = new Asymmetric(rsa, set.Asymmetric);
            _symmetric = new Symmetric(_symmetricKey, set.Symmetric);
            _set = set;
        }

        /// <summary>
        /// Create a client where secure sessions are provided
        /// </summary>
        /// <param name="key">Public key for server</param>
        /// <param name="set">Algorithm set to use</param>
        /// <returns>Client created (not Connect())</returns>
        public static Client Create(PublicKey key, Secure.Algorithm.Set set)
        {
            return new Client(key, set);
        }

        /// <summary>
        /// Connect to a preconfigured server
        /// <param name="serverEP"/>Server IP end point</param>
        /// <param name="retry">Maximum retry to connect</param>
        /// </summary>
        public void Connect(IPEndPoint serverEP, int retry = 100)
        {
            int noneSymmetric = "OK".GetBytes().Length;

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

            while (CanUseStream() == false);

            if (_asymmetric.AsymmetricAlgorithm != null)
            {
                byte[] symmetricKey = _asymmetric.AsymmetricAlgorithm.Encrypt(_symmetricKey, RSAEncryptionPadding.Pkcs1);
                _client.GetStream().Write(symmetricKey, 0, symmetricKey.Length);

                byte[] buffer = new byte[Math.Max(Symmetric.BlockSize(_symmetric.Algorithm), noneSymmetric)];

                int s = 0;
                while (s < buffer.Length)
                    s += _client.GetStream().Read(buffer, s, buffer.Length - s);

                string res = new Symmetric(_symmetricKey, _set.Symmetric).Decrypt(buffer, new byte[Symmetric.BlockSize(_symmetric.Algorithm)]).GetString();

                _symmetric = new Symmetric(_symmetricKey, _set.Symmetric);

                if (res.StartsWith("OK") == false)
                {
                    throw new SecSessRefuesedException();
                }
            }
            else
            {
                _client.GetStream().Write(_symmetricKey, 0, _symmetricKey.Length);

                byte[] buffer = new byte[Math.Max(Symmetric.BlockSize(_symmetric.Algorithm), noneSymmetric)];

                int s = 0;
                while (s < buffer.Length)
                    s += _client.GetStream().Read(buffer, s, buffer.Length - s);

                string res = new Symmetric(_symmetricKey, _set.Symmetric).Decrypt(buffer, new byte[Symmetric.BlockSize(_symmetric.Algorithm)]).GetString();

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
            _client.Dispose();
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
