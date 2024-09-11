using SecSess.Secure;
using SecSess.Tcp;
using System.Net.Sockets;
using System.Security.Cryptography;
using static SecSess.Tcp.Server;

namespace SecSess.Interface
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
        /// <param name="aes">AES support wrapper</param>
        /// <param name="client">A TCP client that actually works</param>
        internal static void InternalWrite(byte[] data, AESWrapper aes, TcpClient client)
        {
            byte[] iv = new byte[16];
            new Random().NextBytes(iv);

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

            byte[] enc = aes.Encrypt(msg, iv);
            byte[] packet = new byte[16 + enc.Length];

            for (int i = 0; i < 16; i++)
            {
                packet[i] = iv[i];
            }
            for (int i = 0; i < enc.Length; i++) 
            {
                packet[i + 16] = enc[i]; 
            }

            client.GetStream().Write(packet, 0, packet.Length);
        }

        /// <summary>
        /// Internal real implementation of a Read method
        /// </summary>
        /// <param name="aes">AES support wrapper</param>
        /// <param name="client">A TCP client that actually works</param>
        /// <returns>Data that read</returns>
        internal static byte[] InternalRead(AESWrapper aes, TcpClient client)
        {
            byte[] iv = new byte[16];

            int s1 = 0;
            while (s1 < iv.Length)
                s1 += client.GetStream().Read(iv, s1, iv.Length - s1);

            byte[] enc = new byte[16];

            int s2 = 0;
            while (s2 < enc.Length)
                s2 += client.GetStream().Read(enc, s2, enc.Length - s2);

            byte[] msg1 = aes.Decrypt(enc, iv);
            iv = enc[0..16];

            int len = BitConverter.ToInt32(msg1[0..4]);
            int blockCount = (len + 4) / 16 + ((len + 4) % 16 == 0 ? 0 : 1);

            byte[] buffer = new byte[(blockCount - 1) * 16];

            if (buffer.Length != 0)
            {
                int s3 = 0;
                while (s3 < buffer.Length)
                    s3 += client.GetStream().Read(buffer, s3, buffer.Length - s3);

                byte[] msg2 = aes.Decrypt(buffer, iv);
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

        public abstract void Write(byte[] data);
        public abstract byte[] Read();
        public abstract bool CanUseStream(StreamType type = StreamType.All);
        public abstract void FlushStream();
    }
}
