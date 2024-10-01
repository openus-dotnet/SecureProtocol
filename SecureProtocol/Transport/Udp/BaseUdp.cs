using Openus.SecureProtocol.Secure.Algorithm;
using Openus.SecureProtocol.Secure.Wrapper;
using Openus.SecureProtocol.Transport.Option;
using Openus.SecureProtocol.Util;
using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;

namespace Openus.SecureProtocol.Transport.Udp
{
    /// <summary>
    /// The abstract base class for UDP client
    /// </summary>
    public abstract class BaseUdp : BaseTransport
    {
        /// <summary>
        /// Get local IP end point
        /// </summary>
        public override IPEndPoint LocalEP { get => (ActuallyClient.Client.LocalEndPoint as IPEndPoint)!; }

        /// <summary>
        /// A UDP client that actually works
        /// </summary>
        protected System.Net.Sockets.UdpClient ActuallyClient { get; private set; }

        /// <summary>
        /// Base client constructor
        /// </summary>
        /// <param name="client">UDP client that actually works</param>
        /// <param name="set">Algorithm set to use</param>
        /// <param name="symmetricKey">Symmetric key to use</param>
        /// <param name="hmacKey">HMAC key to use</param>
        internal BaseUdp(System.Net.Sockets.UdpClient client, Set set, byte[] symmetricKey, byte[] hmacKey)
            : base(set, symmetricKey, hmacKey)
        {
            ActuallyClient = client;
        }

        /// <summary>
        /// Write packet with secure session
        /// </summary>
        /// <param name="remoteEP">Remote end point</param>
        /// <param name="data">Data that write</param>
        public void Write(IPEndPoint remoteEP, byte[] data)
        {
            Debug.WriteLine("UDP WT BFR: ");
            Debug.WriteLine("RAW: " + data.GetByteArrayString());

            if (SymmetricWrapper.Algorithm != SymmetricType.None)
            {
                _sendNonce += (uint)new Random(DateTime.Now.Microsecond).Next(1, 5);

                byte[] iv = new byte[Symmetric.BlockSize(SymmetricWrapper.Algorithm)];
                RandomNumberGenerator.Fill(iv);

                byte[] nonceBit = BitConverter.GetBytes(_sendNonce);
                byte[] lenBit = BitConverter.GetBytes(data.Length);
                byte[] msg = new byte[nonceBit.Length + lenBit.Length + data.Length];

                Buffer.BlockCopy(nonceBit, 0, msg, 0, nonceBit.Length);
                Buffer.BlockCopy(lenBit, 0, msg, nonceBit.Length, lenBit.Length);
                Buffer.BlockCopy(data, 0, msg, nonceBit.Length + lenBit.Length, data.Length);

                Debug.WriteLine("NONCE: " + nonceBit.GetByteArrayString());
                Debug.WriteLine("LEN: " + lenBit.GetByteArrayString());
                Debug.WriteLine("RAW: " + msg.GetByteArrayString());

                byte[]? enc = SymmetricWrapper.Encrypt(msg, iv);

                if (enc == null)
                {
                    throw new SecProtoException(ExceptionCode.EncryptError);
                }

                byte[] packet = new byte[iv.Length + enc.Length];

                Buffer.BlockCopy(iv, 0, packet, 0, iv.Length);
                Buffer.BlockCopy(enc, 0, packet, iv.Length, enc.Length);

                if (HmacKey.Length == 0)
                {
                    Debug.WriteLine("UDP WT AFT: ");
                    Debug.WriteLine("IV: " + iv.GetByteArrayString());
                    Debug.WriteLine("ENC: " + enc.GetByteArrayString());

                    ActuallyClient.Send(packet, packet.Length, remoteEP);
                }
                else
                {
                    byte[] hmacs = new byte[packet.Length + Hash.HashDataSize(AlgorithmSet.Hash)];
                    byte[] hmac = Hash.HmacData(AlgorithmSet.Hash, HmacKey, packet);

                    Buffer.BlockCopy(packet, 0, hmacs, 0, packet.Length);
                    Buffer.BlockCopy(hmac, 0, hmacs, packet.Length, hmac.Length);

                    Debug.WriteLine("UDP WT AFT: ");
                    Debug.WriteLine("IV: " + iv.GetByteArrayString());
                    Debug.WriteLine("ENC: " + enc.GetByteArrayString());
                    Debug.WriteLine("HMAC: " + hmac.GetByteArrayString());

                    ActuallyClient.Send(hmacs, hmacs.Length, remoteEP);
                }
            }
            else
            {
                byte[] lenBit = BitConverter.GetBytes(data.Length);
                byte[] msg = new byte[4 + data.Length];

                Buffer.BlockCopy(lenBit, 0, msg, 0, lenBit.Length);
                Buffer.BlockCopy(data, 0, msg, lenBit.Length, data.Length);

                Debug.WriteLine("TCP WT AFT: ");
                Debug.WriteLine("DATA: " + data.GetByteArrayString());
                Debug.WriteLine("LEN: " + lenBit.GetByteArrayString());
                Debug.WriteLine("RAW: " + msg.GetByteArrayString());

                ActuallyClient.Send(msg, msg.Length, remoteEP);
            }
        }

        /// <summary>
        /// Read packet with secure session
        /// </summary>
        /// <param name="remoteEP">Remote end point</param>
        /// <param name="type">How to handle when problem</param>
        /// <returns>Data that read</returns>
        public byte[] Read(ref IPEndPoint remoteEP, HandlingType type = HandlingType.Ecexption)
        {
            Debug.WriteLine("UDP RD BFR: ");

            if (SymmetricWrapper.Algorithm != SymmetricType.None)
            {
                byte[] all = ActuallyClient.Receive(ref remoteEP);

                byte[] iv = new byte[Symmetric.BlockSize(AlgorithmSet.Symmetric)];
                byte[] enc1 = new byte[Symmetric.BlockSize(AlgorithmSet.Symmetric)];

                Debug.WriteLine("IV: " + iv.GetByteArrayString());

                Buffer.BlockCopy(all, 0, iv, 0, iv.Length);
                Buffer.BlockCopy(all, iv.Length, enc1, 0, enc1.Length);

                byte[]? msg1 = SymmetricWrapper.Decrypt(enc1, iv);

                if (msg1 == null)
                {
                    switch (type)
                    {
                        case HandlingType.Ecexption:
                            throw new SecProtoException(ExceptionCode.DecryptError);
                        case HandlingType.EmptyReturn:
                            return Array.Empty<byte>();
                        default:
                            throw new SecProtoException(ExceptionCode.InvalidHandlingType);
                    }
                }

                uint readNonce = BitConverter.ToUInt32(msg1[0..4]);

                if (readNonce <= _recvNonce)
                {
                    switch (type)
                    {
                        case HandlingType.Ecexption:
                            throw new SecProtoException(ExceptionCode.InvalidNonce);
                        case HandlingType.EmptyReturn:
                            return Array.Empty<byte>();
                        default:
                            throw new SecProtoException(ExceptionCode.InvalidHandlingType);
                    }
                }

                _recvNonce = readNonce;

                int len = BitConverter.ToInt32(msg1[4..8]);
                int blockCount = (8 + len) / enc1.Length + ((8 + len) % enc1.Length == 0 ? 0 : 1);

                byte[] enc2 = new byte[(blockCount - 1) * enc1.Length];

                if (enc2.Length != 0)
                {
                    Buffer.BlockCopy(all, iv.Length + enc1.Length, enc2, 0, enc2.Length);

                    Debug.WriteLine("ENC: " + enc1.Concat(enc2).ToArray().GetByteArrayString());

                    byte[]? msg2 = SymmetricWrapper.Decrypt(enc2, enc1);

                    if (msg2 == null)
                    {
                        switch (type)
                        {
                            case HandlingType.Ecexption:
                                throw new SecProtoException(ExceptionCode.DecryptError);
                            case HandlingType.EmptyReturn:
                                return Array.Empty<byte>();
                            default:
                                throw new SecProtoException(ExceptionCode.InvalidHandlingType);
                        }
                    }

                    byte[] data = new byte[len];

                    Buffer.BlockCopy(msg1, 8, data, 0, msg1.Length - 8);
                    Buffer.BlockCopy(msg2, 0, data, msg1.Length - 8, len - (msg1.Length - 8));

                    if (HmacKey.Length != 0)
                    {
                        byte[] concat = new byte[iv.Length + enc1.Length + enc2.Length];

                        Buffer.BlockCopy(iv, 0, concat, 0, iv.Length);
                        Buffer.BlockCopy(enc1, 0, concat, iv.Length, enc1.Length);
                        Buffer.BlockCopy(enc2, 0, concat, iv.Length + enc1.Length, enc2.Length);

                        byte[] hmacs = new byte[Hash.HashDataSize(AlgorithmSet.Hash)];

                        Buffer.BlockCopy(all, iv.Length + enc1.Length + enc2.Length, hmacs, 0, hmacs.Length);

                        Debug.WriteLine("HMAC: " + hmacs.GetByteArrayString());

                        byte[] compare = Hash.HmacData(AlgorithmSet.Hash, HmacKey, concat);

                        if (compare.SequenceEqual(hmacs) == false)
                        {
                            switch (type)
                            {
                                case HandlingType.Ecexption:
                                    throw new SecProtoException(ExceptionCode.InvalidHmac);
                                case HandlingType.EmptyReturn:
                                    return Array.Empty<byte>();
                                default:
                                    throw new SecProtoException(ExceptionCode.InvalidHandlingType);
                            }
                        }
                    }

                    Debug.WriteLine("UDP RD AFT: ");
                    Debug.WriteLine("NONCE: " + msg1[0..4].GetByteArrayString());
                    Debug.WriteLine("LEN: " + msg1[4..8].GetByteArrayString());
                    Debug.WriteLine("DATA: " + data.GetByteArrayString());
                    Debug.WriteLine("RAW: " + msg1.Concat(msg2).ToArray().GetByteArrayString());

                    return data;
                }
                else
                {
                    byte[] concat = new byte[iv.Length + enc1.Length];

                    Buffer.BlockCopy(iv, 0, concat, 0, iv.Length);
                    Buffer.BlockCopy(enc1, 0, concat, iv.Length, enc1.Length);

                    Debug.WriteLine("ENC: " + enc1.GetByteArrayString());

                    if (HmacKey.Length != 0)
                    {
                        byte[] hmacs = new byte[Hash.HashDataSize(AlgorithmSet.Hash)];

                        Buffer.BlockCopy(all, iv.Length + enc1.Length, hmacs, 0, hmacs.Length);

                        Debug.WriteLine("HMAC: " + hmacs.GetByteArrayString());

                        byte[] compare = Hash.HmacData(AlgorithmSet.Hash, HmacKey, concat);

                        if (compare.SequenceEqual(hmacs) == false)
                        {
                            switch (type)
                            {
                                case HandlingType.Ecexption:
                                    throw new SecProtoException(ExceptionCode.InvalidHmac);
                                case HandlingType.EmptyReturn:
                                    return Array.Empty<byte>();
                                default:
                                    throw new SecProtoException(ExceptionCode.InvalidHandlingType);
                            }
                        }
                    }

                    Debug.WriteLine("UDP RD AFT: ");
                    Debug.WriteLine("NONCE: " + msg1[0..4].GetByteArrayString());
                    Debug.WriteLine("LEN: " + msg1[4..8].GetByteArrayString());
                    Debug.WriteLine("DATA: " + msg1[8..(len + 8)].GetByteArrayString());
                    Debug.WriteLine("RAW: " + msg1.GetByteArrayString());

                    return msg1[8..(len + 8)];
                }
            }
            else
            {
                byte[] all = ActuallyClient.Receive(ref remoteEP);

                byte[] lenBit = new byte[4];

                Buffer.BlockCopy(all, 0, lenBit, 0, lenBit.Length);

                int len = BitConverter.ToInt32(lenBit);
                byte[] msg = new byte[len];

                Buffer.BlockCopy(all, lenBit.Length, msg, 0, msg.Length);

                Debug.WriteLine("UDP RD AFT: ");
                Debug.WriteLine("DATA: " + msg.GetByteArrayString());
                Debug.WriteLine("LEN: " + lenBit.GetByteArrayString());
                Debug.WriteLine("RAW: " + all.GetByteArrayString());

                return msg;
            }
        }

        /// <summary>
        /// Write packet with secure session
        /// </summary>
        /// <param name="ep">Remote end point</param>
        /// <param name="data">Data that write</param>
        public async Task WriteAsync(IPEndPoint ep, byte[] data)
        {
            await Task.Run(() => Write(ep, data));
        }

        /// <summary>
        /// Read packet with secure session
        /// </summary>
        /// <param name="remoteEP">Remote end point</param>
        /// <param name="type">How to handle when problem</param>
        /// <returns>Data that read</returns>
        public async Task<byte[]> ReadAsync(IPEndPoint remoteEP, HandlingType type = HandlingType.Ecexption)
        {
            return await Task.Run(() => Read(ref remoteEP, type));
        }

        /// <summary>
        /// Close the connection
        /// </summary>
        public override void Close()
        {
            ActuallyClient.Close();
            ActuallyClient.Dispose();
        }
    }
}
