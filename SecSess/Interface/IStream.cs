using SecSess.Secure;
using SecSess.Tcp;
using System.Net.Sockets;
using static System.Runtime.InteropServices.JavaScript.JSType;

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
        /// <param name="symmetric">Symmetric secure algorithm</param>
        /// <param name="client">A TCP client that actually works</param>
        internal static void InternalWrite(byte[] data, Symmetric symmetric, TcpClient client)
        {
            if (symmetric.Algorithm != Secure.Algorithm.Symmetric.None)
            {
                int blockSize = Symmetric.BlockSize(symmetric.Algorithm);

                byte[] iv = new byte[blockSize];
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

                byte[] enc = symmetric.Encrypt(msg, iv);
                byte[] packet = new byte[blockSize + enc.Length];

                for (int i = 0; i < blockSize; i++)
                {
                    packet[i] = iv[i];
                }
                for (int i = 0; i < enc.Length; i++)
                {
                    packet[i + blockSize] = enc[i];
                }

                client.GetStream().Write(packet, 0, packet.Length);
            }
            else
            {
                byte[] lenBit = BitConverter.GetBytes(data.Length);
                byte[] msg = new byte[4 + data.Length];

                for (int i = 0; i < 4; i++)
                {
                    msg[i] = lenBit[i];
                }
                for (int i = 0; i < data.Length; i++)
                {
                    msg[i + 4] = data[i];
                }

                client.GetStream().Write(msg, 0, msg.Length);
            }
        }

        /// <summary>
        /// Internal real implementation of a Read method
        /// </summary>
        /// <param name="symmetric">Symmetric secure algorithm</param>
        /// <param name="client">A TCP client that actually works</param>
        /// <returns>Data that read</returns>
        internal static byte[] InternalRead(Symmetric symmetric, TcpClient client)
        {
            if (symmetric.Algorithm != Secure.Algorithm.Symmetric.None)
            {
                int blockSize = Symmetric.BlockSize(symmetric.Algorithm);

                byte[] iv = new byte[blockSize];

                int s1 = 0;
                while (s1 < iv.Length)
                    s1 += client.GetStream().Read(iv, s1, iv.Length - s1);

                byte[] enc = new byte[blockSize];

                int s2 = 0;
                while (s2 < enc.Length)
                    s2 += client.GetStream().Read(enc, s2, enc.Length - s2);

                byte[] msg1 = symmetric.Decrypt(enc, iv);
                iv = enc[0..blockSize];

                int len = BitConverter.ToInt32(msg1[0..4]);
                int blockCount = (len + 4) / blockSize + ((len + 4) % blockSize == 0 ? 0 : 1);

                byte[] buffer = new byte[(blockCount - 1) * blockSize];

                if (buffer.Length != 0)
                {
                    int s3 = 0;
                    while (s3 < buffer.Length)
                        s3 += client.GetStream().Read(buffer, s3, buffer.Length - s3);

                    byte[] msg2 = symmetric.Decrypt(buffer, iv);
                    byte[] data = new byte[len];

                    int offset = 0;

                    for (; offset < blockSize - 4; offset++)
                    {
                        data[offset] = msg1[offset + 4];
                    }
                    for (; offset < data.Length; offset++)
                    {
                        data[offset] = msg2[offset - (blockSize - 4)];
                    }

                    return data;
                }
                else
                {
                    return msg1[4..(len + 4)];
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
