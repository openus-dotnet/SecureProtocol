using Openus.SecureProtocol.Key.Asymmetric;
using Openus.SecureProtocol.Secure.Algorithm;
using Openus.SecureProtocol.Secure.Wrapper;
using Openus.SecureProtocol.Util;
using System.Net;
using System.Net.Sockets;

namespace Openus.SecureProtocol.Transport.Tcp
{
    /// <summary>
    /// TCP client with secure sessions
    /// </summary>
    public class TcpClient : BaseTcp
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
        private TcpClient(BaseAsymmetricKey? parameter, Set set, byte[] symmetricKey, byte[] hmacKey)
            : base(new System.Net.Sockets.TcpClient(), set, symmetricKey, hmacKey)
        {
            _asymmetric = new Asymmetric(parameter, set.Asymmetric);
        }

        /// <summary>
        /// Create a client without secure session
        /// </summary>
        /// <returns>Client created (already not Connect())</returns>
        public static TcpClient Craete()
        {
            var keys = GenerateKeySet(Set.NoneSet);

            return new TcpClient(null, Set.NoneSet, keys.Item1, keys.Item2);
        }
        /// <summary>
        /// Create a client where secure sessions are provided
        /// </summary>
        /// <param name="key">Public key for server</param>
        /// <param name="set">Algorithm set to use</param>
        /// <returns>Client created (already not Connect())</returns>
        public static TcpClient Create(PublicKey? key, Set set)
        {
            var keys = GenerateKeySet(set);

            return new TcpClient(key, set, keys.Item1, keys.Item2);
        }

        /// <summary>
        /// Connect to a preconfigured server
        /// </summary>
        /// <param name="serverEP">Server IP end point</param>
        /// <param name="retry">Maximum retry to connect</param>
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

            if (SymmetricWrapper.Algorithm != SymmetricType.None)
            {
                byte[] buffer = new byte[SymmetricKey.Length + HmacKey.Length];

                Buffer.BlockCopy(SymmetricKey, 0, buffer, 0, SymmetricKey.Length);
                Buffer.BlockCopy(HmacKey, 0, buffer, SymmetricKey.Length, HmacKey.Length);

                byte[]? enc = _asymmetric.Encrypt(buffer);

                if (enc == null)
                {
                    throw new SecSessException(ExceptionCode.EncryptError);
                }

                ActuallyClient.GetStream().Write(enc, 0, enc.Length);

                byte[] response = Read();
                byte[] compare = Hash.HashData(AlgorithmSet.Hash, buffer);

                if (compare.SequenceEqual(response) == false)
                {
                    throw new SecSessException(ExceptionCode.InvalidHmac);
                }
            }
            else if (SymmetricWrapper.Algorithm == SymmetricType.None)
            {

            }
            else
            {
                throw new SecSessException(ExceptionCode.InvalidHandlingType);
            }
        }
        /// <summary>
        /// Connect to a preconfigured server
        /// </summary>
        /// <param name="serverEP">Server IP end point</param>
        /// <param name="retry">Maximum retry to connect</param>
        public async Task ConnectAsync(IPEndPoint serverEP, int retry = 0)
        {
            await Task.Run(() => Connect(serverEP, retry));
        }
    }
}
