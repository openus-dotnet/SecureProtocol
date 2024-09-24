﻿using SecSess.Secure.Wrapper;
using SecSess.Tcp;
using SecSess.Util;
using System.Buffers.Text;
using System.Diagnostics;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SecSess.Interface.Tcp
{
    /// <summary>
    /// The interface that manages the stream (mainly on the client side)
    /// </summary>
    public interface IStream
    {
        /// <summary>
        /// Internal real implementation of a Write method
        /// </summary>
        /// <param name="data">Data that write</param>
        /// <param name="symmetric">Symmetric secure algorithm</param>
        /// <param name="hmacKey">HMAC key for auth</param>
        /// <param name="hash">Hash algorithm to use</param>
        /// <param name="client">A TCP client that actually works</param>
        /// <param name="nonce">Nonce for preventing retransmission attacks</param>
        internal static void InternalWrite(byte[] data, Symmetric symmetric, byte[] hmacKey,
            Secure.Algorithm.Hash hash, TcpClient client, ref int nonce)
        {
            if (symmetric.Algorithm != Secure.Algorithm.Symmetric.None)
            {
                nonce += new Random(DateTime.Now.Microsecond).Next(1, 10);

                byte[] iv = new byte[Symmetric.BlockSize(symmetric.Algorithm)];
                new Random().NextBytes(iv);

                byte[] nonceBit = BitConverter.GetBytes(nonce);
                byte[] lenBit = BitConverter.GetBytes(data.Length);
                byte[] msg = new byte[nonceBit.Length + lenBit.Length + data.Length];

                Buffer.BlockCopy(nonceBit, 0, msg, 0, nonceBit.Length);
                Buffer.BlockCopy(lenBit, 0, msg, nonceBit.Length, lenBit.Length);
                Buffer.BlockCopy(data, 0, msg, nonceBit.Length + lenBit.Length, data.Length);

                byte[] enc = symmetric.Encrypt(msg, iv);
                byte[] packet = new byte[iv.Length + enc.Length];

                Buffer.BlockCopy(iv, 0, packet, 0, iv.Length);
                Buffer.BlockCopy(enc, 0, packet, iv.Length, enc.Length);

                if (hmacKey.Length == 0)
                {
                    client.GetStream().Write(packet, 0, packet.Length);
                }
                else
                {
                    byte[] hmacs = new byte[packet.Length + Hash.HashDataSize(hash)];
                    byte[] hmac = Hash.HMacData(hash, hmacKey, packet);

                    Buffer.BlockCopy(packet, 0, hmacs, 0, packet.Length);
                    Buffer.BlockCopy(hmac, 0, hmacs, packet.Length, hmac.Length);

                    client.GetStream().Write(hmacs, 0, hmacs.Length);
                }
            }
            else
            {
                byte[] lenBit = BitConverter.GetBytes(data.Length);
                byte[] msg = new byte[4 + data.Length];

                Buffer.BlockCopy(lenBit, 0, msg, 0, lenBit.Length);
                Buffer.BlockCopy(data, 0, msg, lenBit.Length, data.Length);

                client.GetStream().Write(msg, 0, msg.Length);
            }
        }

        /// <summary>
        /// Internal real implementation of a Read method
        /// </summary>
        /// <param name="symmetric">Symmetric secure algorithm</param>
        /// <param name="hmacKey">HMAC key for auth</param>
        /// <param name="hash">Hash algorithm to use</param>
        /// <param name="client">A TCP client that actually works</param>
        /// <param name="nonce">Nonce for preventing retransmission attacks</param>
        /// <returns>Data that read</returns>
        internal static byte[] InternalRead(Symmetric symmetric, byte[] hmacKey,
            Secure.Algorithm.Hash hash, TcpClient client, ref int nonce)
        {
            if (symmetric.Algorithm != Secure.Algorithm.Symmetric.None)
            {
                byte[] iv = new byte[Symmetric.BlockSize(symmetric.Algorithm)];

                int s1 = 0;
                while (s1 < iv.Length)
                    s1 += client.GetStream().Read(iv, s1, iv.Length - s1);

                byte[] enc1 = new byte[iv.Length];

                int s2 = 0;
                while (s2 < enc1.Length)
                    s2 += client.GetStream().Read(enc1, s2, enc1.Length - s2);

                byte[] msg1 = symmetric.Decrypt(enc1, iv);

                int readNonce = BitConverter.ToInt32(msg1[0..4]);

                if (readNonce <= nonce)
                {
                    throw new AuthenticationException("Nonce is incorrected.");
                }

                nonce = readNonce;

                int len = BitConverter.ToInt32(msg1[4..8]);
                int blockCount = (8 + len) / enc1.Length + ((8 + len) % enc1.Length == 0 ? 0 : 1);

                byte[] enc2 = new byte[(blockCount - 1) * enc1.Length];

                if (enc2.Length != 0)
                {
                    int s3 = 0;
                    while (s3 < enc2.Length)
                        s3 += client.GetStream().Read(enc2, s3, enc2.Length - s3);

                    byte[] msg2 = symmetric.Decrypt(enc2, enc1);
                    byte[] data = new byte[len];

                    Buffer.BlockCopy(msg1, 8, data, 0, msg1.Length - 8);
                    Buffer.BlockCopy(msg2, 0, data, msg1.Length - 8, len - (msg1.Length - 8));

                    if (hmacKey.Length != 0)
                    {
                        byte[] concat = new byte[iv.Length + enc1.Length + enc2.Length];

                        Buffer.BlockCopy(iv, 0, concat, 0, iv.Length);
                        Buffer.BlockCopy(enc1, 0, concat, iv.Length, enc1.Length);
                        Buffer.BlockCopy(enc2, 0, concat, iv.Length + enc1.Length, enc2.Length);

                        byte[] hmacs = new byte[Hash.HashDataSize(hash)];

                        int s4 = 0;
                        while (s4 < hmacs.Length)
                            s4 += client.GetStream().Read(hmacs, s4, hmacs.Length - s4);

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

                    byte[] hmacs = new byte[Hash.HashDataSize(hash)];

                    int s4 = 0;
                    while (s4 < hmacs.Length)
                        s4 += client.GetStream().Read(hmacs, s4, hmacs.Length - s4);

                    byte[] compare = Hash.HMacData(hash, hmacKey, concat);

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
                    s1 += client.GetStream().Read(lenBit, s1, lenBit.Length - s1);

                int len = BitConverter.ToInt32(lenBit);
                byte[] msg = new byte[len];

                int s2 = 0;
                while (s2 < msg.Length)
                    s2 += client.GetStream().Read(msg, s2, msg.Length - s2);

                return msg;
            }
        }

        public abstract void Write(byte[] data);
        public abstract byte[] Read();

        public abstract bool CanUseStream(StreamType type = StreamType.All);
        public abstract void FlushStream();
    }
}