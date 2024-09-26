using Openus.Net.SecSess.Secure.Wrapper;
using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;

namespace Openus.Net.SecSess.Interface.Udp
{
    internal interface IStream
    {
        /// <summary>
        /// Internal real implementation of a Write method
        /// </summary>
        /// <param name="data">Data that write</param>
        /// <param name="symmetric">Symmetric secure algorithm</param>
        /// <param name="hmacKey">HMAC key for auth</param>
        /// <param name="hash">Hash algorithm to use</param>
        /// <param name="client">A UDP client that actually works</param>
        /// <param name="remoteEP">Remote IP end point to write or read</param>
        internal static void InternalWrite(byte[] data, Symmetric symmetric, byte[] hmacKey, Secure.Algorithm.Hash hash, UdpClient client, IPEndPoint remoteEP)
        {
            if (symmetric.Algorithm != Secure.Algorithm.Symmetric.None)
            {
                byte[] iv = new byte[Symmetric.BlockSize(symmetric.Algorithm)];
                new Random().NextBytes(iv);

                byte[] lenBit = BitConverter.GetBytes(data.Length);
                byte[] msg = new byte[data.Length + 4];

                Buffer.BlockCopy(lenBit, 0, msg, 0, lenBit.Length);
                Buffer.BlockCopy(data, 0, msg, lenBit.Length, data.Length);

                byte[] enc = symmetric.Encrypt(msg, iv);
                byte[] packet = new byte[iv.Length + enc.Length];

                Buffer.BlockCopy(iv, 0, packet, 0, iv.Length);
                Buffer.BlockCopy(enc, 0, packet, iv.Length, enc.Length);

                if (hmacKey.Length == 0)
                {
                    client.Send(packet, packet.Length, remoteEP);
                }
                else
                {
                    byte[] hmacs = new byte[packet.Length + Hash.HashDataSize(hash)];

                    Buffer.BlockCopy(packet, 0, hmacs, 0, packet.Length);
                    Buffer.BlockCopy(Hash.HMacData(hash, hmacKey, packet), 0, hmacs, packet.Length, Hash.HashDataSize(hash));

                    client.Send(hmacs, hmacs.Length, remoteEP);
                }
            }
            else
            {
                byte[] lenBit = BitConverter.GetBytes(data.Length);
                byte[] msg = new byte[4 + data.Length];

                Buffer.BlockCopy(lenBit, 0, msg, 0, lenBit.Length);
                Buffer.BlockCopy(data, 0, msg, lenBit.Length, data.Length);

                client.Send(msg, msg.Length, remoteEP);
            }
        }

        /// <summary>
        /// Internal real implementation of a Read method
        /// </summary>
        /// <param name="symmetric">Symmetric secure algorithm</param>
        /// <param name="hmacKey">HMAC key for auth</param>
        /// <param name="hash">Hash algorithm to use</param>
        /// <param name="client">A UDP client that actually works</param>
        /// <param name="remoteEP">Remote IP end point to write or read</param>
        /// <returns>Data that read</returns>
        internal static byte[] InternalRead(Symmetric symmetric, byte[] hmacKey, Secure.Algorithm.Hash hash, UdpClient client, ref IPEndPoint remoteEP)
        {
            if (symmetric.Algorithm != Secure.Algorithm.Symmetric.None)
            {
                byte[] fullData = client.Receive(ref remoteEP);

                byte[] iv = fullData[0..Symmetric.BlockSize(symmetric.Algorithm)];
                byte[] enc1 = fullData[iv.Length..(iv.Length + Symmetric.BlockSize(symmetric.Algorithm))];

                byte[] msg1 = symmetric.Decrypt(enc1, iv);

                int len = BitConverter.ToInt32(msg1[0..4]);
                int blockCount = (len + 4) / enc1.Length + ((len + 4) % enc1.Length == 0 ? 0 : 1);

                if ((blockCount - 1) * enc1.Length != 0)
                {
                    byte[] enc2 = fullData[(iv.Length + enc1.Length)..(iv.Length + blockCount * enc1.Length)];

                    byte[] msg2 = symmetric.Decrypt(enc2, enc1);
                    byte[] data = new byte[len];

                    Buffer.BlockCopy(msg1, 4, data, 0, msg1.Length - 4);
                    Buffer.BlockCopy(msg2, 0, data, msg1.Length - 4, len - (msg1.Length - 4));

                    if (hmacKey.Length != 0)
                    {
                        byte[] concat = new byte[iv.Length + enc1.Length + enc2.Length];

                        Buffer.BlockCopy(iv, 0, concat, 0, iv.Length);
                        Buffer.BlockCopy(enc1, 0, concat, iv.Length, enc1.Length);
                        Buffer.BlockCopy(enc2, 0, concat, iv.Length + enc1.Length, enc2.Length);

                        byte[] hmacs = fullData[(iv.Length + enc1.Length + enc2.Length)
                            ..(iv.Length + enc1.Length + enc2.Length + Hash.HashDataSize(hash))];

                        byte[] compare = Hash.HMacData(hash, hmacKey, concat);

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

                    byte[] hmacs = fullData[(iv.Length + enc1.Length)
                        ..(iv.Length + enc1.Length + Hash.HashDataSize(hash))];

                    byte[] compare = Hash.HMacData(hash, hmacKey, concat);

                    if (compare.SequenceEqual(hmacs) == false)
                    {
                        throw new AuthenticationException("HMAC authentication is failed.");
                    }

                    return msg1[4..(len + 4)];
                }
            }
            else
            {
                byte[] fullData = client.Receive(ref remoteEP);
                byte[] lenBit = fullData[0..4];

                int len = BitConverter.ToInt32(lenBit);
                byte[] msg = fullData[lenBit.Length..(4 + len)];

                return msg;
            }
        }

        public abstract void Write(byte[] data, IPEndPoint remoteEP);
        public abstract byte[] Read(ref IPEndPoint remoteEP);
    }
}
