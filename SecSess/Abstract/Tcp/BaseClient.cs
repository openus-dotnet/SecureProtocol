using Openus.Net.SecSess.Secure.Algorithm;
using Openus.Net.SecSess.Secure.Wrapper;
using Openus.Net.SecSess.Transport.Tcp;
using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;

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

        /// <summary>
        /// Write packet with secure session
        /// </summary>
        /// <param name="data">Data that write to server</param>
        public void Write(byte[] data)
        {
            if (SymmetricWrapper.Algorithm != SymmetricType.None)
            {
                _nonce += new Random(DateTime.Now.Microsecond).Next(1, 10);

                byte[] iv = new byte[Symmetric.BlockSize(SymmetricWrapper.Algorithm)];
                new Random().NextBytes(iv);

                byte[] nonceBit = BitConverter.GetBytes(_nonce);
                byte[] lenBit = BitConverter.GetBytes(data.Length);
                byte[] msg = new byte[nonceBit.Length + lenBit.Length + data.Length];

                Buffer.BlockCopy(nonceBit, 0, msg, 0, nonceBit.Length);
                Buffer.BlockCopy(lenBit, 0, msg, nonceBit.Length, lenBit.Length);
                Buffer.BlockCopy(data, 0, msg, nonceBit.Length + lenBit.Length, data.Length);

                byte[] enc = SymmetricWrapper.Encrypt(msg, iv);
                byte[] packet = new byte[iv.Length + enc.Length];

                Buffer.BlockCopy(iv, 0, packet, 0, iv.Length);
                Buffer.BlockCopy(enc, 0, packet, iv.Length, enc.Length);

                if (HMacKey.Length == 0)
                {
                    ActuallyClient.GetStream().Write(packet, 0, packet.Length);
                }
                else
                {
                    byte[] hmacs = new byte[packet.Length + Hash.HashDataSize(AlgorithmSet.Hash)];
                    byte[] hmac = Hash.HMacData(AlgorithmSet.Hash, HMacKey, packet);

                    Buffer.BlockCopy(packet, 0, hmacs, 0, packet.Length);
                    Buffer.BlockCopy(hmac, 0, hmacs, packet.Length, hmac.Length);

                    ActuallyClient.GetStream().Write(hmacs, 0, hmacs.Length);
                }
            }
            else
            {
                byte[] lenBit = BitConverter.GetBytes(data.Length);
                byte[] msg = new byte[4 + data.Length];

                Buffer.BlockCopy(lenBit, 0, msg, 0, lenBit.Length);
                Buffer.BlockCopy(data, 0, msg, lenBit.Length, data.Length);

                ActuallyClient.GetStream().Write(msg, 0, msg.Length);
            }
        }

        /// <summary>
        /// Read packet with secure session
        /// </summary>
        /// <returns>Data that read from server</returns>
        public byte[] Read()
        {
            if (SymmetricWrapper.Algorithm != SymmetricType.None)
            {
                byte[] iv = new byte[Symmetric.BlockSize(SymmetricWrapper.Algorithm)];

                int s1 = 0;
                while (s1 < iv.Length)
                    s1 += ActuallyClient.GetStream().Read(iv, s1, iv.Length - s1);

                byte[] enc1 = new byte[iv.Length];

                int s2 = 0;
                while (s2 < enc1.Length)
                    s2 += ActuallyClient.GetStream().Read(enc1, s2, enc1.Length - s2);

                byte[] msg1 = SymmetricWrapper.Decrypt(enc1, iv);

                int readNonce = BitConverter.ToInt32(msg1[0..4]);

                if (readNonce <= _nonce)
                {
                    throw new AuthenticationException("_nonce is incorrected.");
                }

                _nonce = readNonce;

                int len = BitConverter.ToInt32(msg1[4..8]);
                int blockCount = (8 + len) / enc1.Length + ((8 + len) % enc1.Length == 0 ? 0 : 1);

                byte[] enc2 = new byte[(blockCount - 1) * enc1.Length];

                if (enc2.Length != 0)
                {
                    int s3 = 0;
                    while (s3 < enc2.Length)
                        s3 += ActuallyClient.GetStream().Read(enc2, s3, enc2.Length - s3);

                    byte[] msg2 = SymmetricWrapper.Decrypt(enc2, enc1);
                    byte[] data = new byte[len];

                    Buffer.BlockCopy(msg1, 8, data, 0, msg1.Length - 8);
                    Buffer.BlockCopy(msg2, 0, data, msg1.Length - 8, len - (msg1.Length - 8));

                    if (HMacKey.Length != 0)
                    {
                        byte[] concat = new byte[iv.Length + enc1.Length + enc2.Length];

                        Buffer.BlockCopy(iv, 0, concat, 0, iv.Length);
                        Buffer.BlockCopy(enc1, 0, concat, iv.Length, enc1.Length);
                        Buffer.BlockCopy(enc2, 0, concat, iv.Length + enc1.Length, enc2.Length);

                        byte[] hmacs = new byte[Hash.HashDataSize(AlgorithmSet.Hash)];

                        int s4 = 0;
                        while (s4 < hmacs.Length)
                            s4 += ActuallyClient.GetStream().Read(hmacs, s4, hmacs.Length - s4);

                        byte[] compare = Hash.HMacData(AlgorithmSet.Hash, HMacKey, concat);

                        if (compare.SequenceEqual(hmacs) == false)
                        {
                            throw new AuthenticationException("HMAC authentication is failed.");
                        }
                    }

                    return data;
                }
                else
                {
                    byte[] concat = new byte[iv.Length + enc1.Length];

                    Buffer.BlockCopy(iv, 0, concat, 0, iv.Length);
                    Buffer.BlockCopy(enc1, 0, concat, iv.Length, enc1.Length);

                    byte[] hmacs = new byte[Hash.HashDataSize(AlgorithmSet.Hash)];

                    int s4 = 0;
                    while (s4 < hmacs.Length)
                        s4 += ActuallyClient.GetStream().Read(hmacs, s4, hmacs.Length - s4);

                    byte[] compare = Hash.HMacData(AlgorithmSet.Hash, HMacKey, concat);

                    if (compare.SequenceEqual(hmacs) == false)
                    {
                        throw new AuthenticationException("HMAC authentication is failed.");
                    }

                    return msg1[8..(len + 8)];
                }
            }
            else
            {
                byte[] lenBit = new byte[4];

                int s1 = 0;
                while (s1 < lenBit.Length)
                    s1 += ActuallyClient.GetStream().Read(lenBit, s1, lenBit.Length - s1);

                int len = BitConverter.ToInt32(lenBit);
                byte[] msg = new byte[len];

                int s2 = 0;
                while (s2 < msg.Length)
                    s2 += ActuallyClient.GetStream().Read(msg, s2, msg.Length - s2);

                return msg;
            }
        }

        /// <summary>
        /// Determine if tcp client state is available
        /// </summary>
        /// <param name="type">The type of client state to judge</param>
        /// <returns></returns>
        public bool CanUseStream(StreamType type = StreamType.All)
        {
            return (type.HasFlag(StreamType.Connect) == true ? ActuallyClient.Connected : true)
                && (type.HasFlag(StreamType.Read) == true ? ActuallyClient.GetStream().CanRead : true)
                && (type.HasFlag(StreamType.Write) == true ? ActuallyClient.GetStream().CanWrite : true);
        }

        /// <summary>
        /// Flushes data from stream
        /// </summary>
        public void FlushStream()
        {
            ActuallyClient.GetStream().Flush();
        }

        /// <summary>
        /// Write packet with secure session
        /// </summary>
        /// <param name="data">Data that write to server</param>
        public async Task WriteAsync(byte[] data)
        {
            await Task.Run(() => Write(data));
        }

        /// <summary>
        /// Read packet with secure session
        /// </summary>
        /// <returns>Data that read from server</returns>
        public async Task<byte[]> ReadAsync()
        {
            return await Task.Run(() => Read());
        }

        /// <summary>
        /// Flushes data from stream
        /// </summary>
        public async Task FlushStreamAsync()
        {
            await Task.Run(() => FlushStream());
        }
    }
}
