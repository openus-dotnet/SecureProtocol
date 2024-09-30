using Openus.SecSess.Key.Session;
using Openus.SecSess.Secure.Algorithm;
using System.Net;

namespace Openus.SecSess.Transport.Udp
{
    /// <summary>
    /// UDP client with secure sessions
    /// </summary>
    public class UdpClient : BaseUdp
    {
        /// <summary>
        /// Create client
        /// </summary>
        /// <param name="endPoint">UDP client end point</param>
        /// <param name="set">Algorithm set to use</param>
        /// <param name="hmacKey">HMAC key to use</param>
        /// <param name="symmetricKey">Symmetric key to use</param>
        private UdpClient(IPEndPoint endPoint, Set set, byte[] symmetricKey, byte[] hmacKey)
            : base(new System.Net.Sockets.UdpClient(endPoint), set, symmetricKey, hmacKey) { }

        /// <summary>
        /// Create a client with secure session
        /// </summary>
        /// <param name="endPoint">UDP client end point</param>
        /// <param name="set">SecSess key sey</param>
        /// <returns>Client created</returns>
        public static UdpClient Craete(IPEndPoint endPoint, KeySet set)
        {
            return new UdpClient(endPoint, set.AlgorithmSet, set.SymmetricKey, set.HmacKey);
        }
        /// <summary>
        /// Create a client without secure session
        /// </summary>
        /// <returns>Client created (already not Connect())</returns>
        public static UdpClient Craete(IPEndPoint endPoint)
        {
            var keys = GenerateKeySet(Set.NoneSet);

            return new UdpClient(endPoint, Set.NoneSet, keys.Item1, keys.Item2);
        }
    }
}
