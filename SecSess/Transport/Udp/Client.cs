using Openus.Net.SecSess.Secure.Wrapper;
using Openus.Net.SecSess.Interface.Udp;
using System.Net;
using System.Net.Sockets;
using Openus.Net.SecSess.Secure.Algorithm;

namespace Openus.Net.SecSess.Transport.Udp
{
    /// <summary>
    /// UDP server with secure sessions
    /// </summary>
    public class Client : IStream
    {
        /// <summary>
        /// A UDP client that actually works
        /// </summary>
        private UdpClient _client;
        /// <summary>
        /// Symmetric wrapper
        /// </summary>
        private Symmetric _symmetric;
        /// <summary>
        /// HMAC key
        /// </summary>
        private byte[] _hamcKey;
        /// <summary>
        /// Algorithm set to use
        /// </summary>
        private Set _set;

        /// <summary>
        /// General constructor for UDP client
        /// </summary>
        /// <param name="client">A UDP client that actually works</param>
        /// <param name="parameters">Symmetric wrapper</param>
        /// <param name="hmacKey">HMAC key</param>
        /// <param name="set">Algorithm set to use</param>
        private Client(UdpClient client, Symmetric parameters, byte[] hmacKey, Set set)
        {
            _client = client;
            _symmetric = parameters;
            _set = set;
            _hamcKey = hmacKey;
        }

        /// <summary>
        /// Create a server where secure sessions are provided
        /// </summary>
        /// <param name="localEP">Loacl IP end point</param>
        /// <param name="symmetricKey">Symmetric key for secure session</param>
        /// <param name="set">Algorithm set to use</param>
        /// <returns>Server created (not Start())</returns>
        public static Client Create(IPEndPoint localEP, byte[] symmetricKey, byte[] hmacKey, Set set)
        {
            return new Client(new UdpClient(localEP), new Symmetric(symmetricKey, set.Symmetric), hmacKey, set);
        }

        /// <summary>
        /// Read datagram with secure session
        /// </summary>
        /// <param name="remoteEP">Remote IP end point from read</param>
        /// <returns>Data that read from other client</returns>
        public byte[] Read(ref IPEndPoint remoteEP)
        {
            return IStream.InternalRead(_symmetric, _hamcKey, _set.Hash, _client, ref remoteEP);
        }

        /// <summary>
        /// Write datagram with secure session
        /// </summary>
        /// <param name="data">Data that write to toher client</param>
        /// <param name="remoteEP">Remote IP end point to write</param>
        public void Write(byte[] data, IPEndPoint remoteEP)
        {
            IStream.InternalWrite(data, _symmetric, _hamcKey, _set.Hash, _client, remoteEP);
        }
    }
}
