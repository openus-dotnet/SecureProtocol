using Openus.Net.SecSess.Key.Asymmetric;
using Openus.Net.SecSess.Secure.Algorithm;
using Openus.Net.SecSess.Secure.Wrapper;
using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;

namespace Openus.Net.SecSess.Transport.Tcp
{
    /// <summary>
    /// TCP client with secure sessions
    /// </summary>
    public class Client : BaseClient
    {
        /// <summary>
        /// Asymmetric algorithm set without private key for client
        /// </summary>
        private Asymmetric _asymmetric;

        /// <summary>
        /// Create client
        /// </summary>
        /// <param name="parameter">Asymmetric key base without private key for client</param>
        /// <param name="set">Algorithm set to use</param>
        /// <param name="hmacKey">HMAC key to use</param>
        /// <param name="symmetricKey">Symmetric key to use</param>
        private Client(BaseAsymmetricKey? parameter, Set set, byte[] symmetricKey, byte[] hmacKey)
            : base(new TcpClient(), set, symmetricKey, hmacKey)
        {
            _asymmetric = new Asymmetric(parameter, set.Asymmetric);
        }

        /// <summary>
        /// Create a client without secure session
        /// </summary>
        /// <returns>Client created (already not Connect())</returns>
        public static Client Craete()
        {
            var keys = GenerateKeySet(Set.NoneSet);

            return new Client(null, Set.NoneSet, keys.Item1, keys.Item2);
        }
        /// <summary>
        /// Create a client where secure sessions are provided
        /// </summary>
        /// <param name="key">Public key for server</param>
        /// <param name="set">Algorithm set to use</param>
        /// <returns>Client created (already not Connect())</returns>
        public static Client Create(PublicKey? key, Set set)
        {
            var keys = GenerateKeySet(set);

            return new Client(key, set, keys.Item1, keys.Item2);
        }

        /// <summary>
        /// Generate symmetric session key and HMAC key
        /// </summary>
        /// <param name="set">Algorithm set to use</param>
        /// <returns>(Symmetric key, HMAC key)</returns>
        private static (byte[], byte[]) GenerateKeySet(Set set)
        {
            byte[] symmetricKey = new byte[Symmetric.KeySize(set.Symmetric)];
            byte[] hmacKey = new byte[Hash.HMacKeySize(set.Hash)];

            RandomNumberGenerator.Fill(symmetricKey);
            RandomNumberGenerator.Fill(hmacKey);

            return (symmetricKey, hmacKey);
        }

        /// <summary>
        /// Close the TCP client
        /// </summary>
        public void Close()
        {
            ActuallyClient.Close();
            ActuallyClient.Dispose();
        }

        /// <summary>
        /// Connect to a preconfigured server
        /// <param name="serverEP"/>Server IP end point</param>
        /// <param name="retry">Maximum retry to connect</param>
        /// </summary>
        public void Connect(IPEndPoint serverEP, int retry = 0)
        {
            ArgumentOutOfRangeException.ThrowIfNegative(retry);

            if (retry == 0)
            {
                ActuallyClient.Connect(serverEP);
            }
            else
            {
                for (int i = 0; i <= retry; i++)
                {
                    try
                    {
                        ActuallyClient.Connect(serverEP);

                        break;
                    }
                    catch (SocketException)
                    {
                        continue;
                    }
                }
            }

            while (CanUseStream() == false) ;

            if (_asymmetric.AsymmetricAlgorithm != null && SymmetricWrapper.Algorithm != SymmetricType.None)
            {
                byte[] buffer = new byte[SymmetricKey.Length + HMacKey.Length];

                Buffer.BlockCopy(SymmetricKey, 0, buffer, 0, SymmetricKey.Length);
                Buffer.BlockCopy(HMacKey, 0, buffer, SymmetricKey.Length, HMacKey.Length);

                byte[] enc = _asymmetric.Encrypt(buffer);
                ActuallyClient.GetStream().Write(enc, 0, enc.Length);

                byte[] response = Read();
                byte[] compare = Hash.HashData(AlgorithmSet.Hash, buffer);

                if (compare.SequenceEqual(response) == false)
                {
                    throw new AuthenticationException("Failed to create a secure session.");
                }
            }
            else if (_asymmetric.AsymmetricAlgorithm == null && SymmetricWrapper.Algorithm == SymmetricType.None)
            {

            }
            else
            {
                throw new InvalidOperationException("Invalid combination between asymmetric to symmetric algorithm.");
            }
        }
        /// <summary>
        /// Connect to a preconfigured server
        /// <param name="serverEP"/>Server IP end point</param>
        /// <param name="retry">Maximum retry to connect</param>
        /// </summary>
        public async Task ConnectAsync(IPEndPoint serverEP, int retry = 0)
        {
            await Task.Run(() => Connect(serverEP, retry));
        }
    }
}
