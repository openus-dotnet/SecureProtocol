using SecSess.Key;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace SecSess.Tcp
{
    /// <summary>
    /// TCP server with secure sessions
    /// </summary>
    public class Server
    {
        /// <summary>
        /// A TCP listener that actually works
        /// </summary>
        private TcpListener _listener;
        /// <summary>
        /// RSA with private key for server
        /// </summary>
        private RSA _rsa;

        /// <summary>
        /// General constructor for server
        /// </summary>
        /// <param name="listener">A TCP listener that actually works</param>
        /// <param name="parameters">RSA parameters with private values for server</param>
        private Server(TcpListener listener, RSAParameters parameters) 
        {
            _listener = listener;
            _rsa = RSA.Create(parameters);
        }

        /// <summary>
        /// Create a server where secure sessions are provided
        /// </summary>
        /// <param name="ip">IP string like (X.X.X.X)</param>
        /// <param name="port">Port number</param>
        /// <param name="key">Private Key for Server</param>
        /// <returns>Server created (not Start()</returns>
        public static Server Create(string ip, int port, PrivateKey key)
        {
            return new Server(new TcpListener(IPEndPoint.Parse($"{ip}:{port}")), key.InnerRSA);
        }
        /// <summary>
        /// Create a server where secure sessions are provided
        /// </summary>
        /// <param name="ipEndPoint">IP string like (X.X.X.X:X)</param>
        /// <param name="key">Private Key for Server</param>
        /// <returns>Server created (not Start()</returns>
        public static Server Create(string ipEndPoint, PrivateKey key)
        {
            return new Server(new TcpListener(IPEndPoint.Parse(ipEndPoint)), key.InnerRSA);
        }
        /// <summary>
        /// Create a server where secure sessions are provided
        /// </summary>
        /// <param name="address">IP address</param>
        /// <param name="port">Port number</param>
        /// <param name="key">Private Key for Server</param>
        /// <returns>Server created (not Start()</returns>
        public static Server Create(IPAddress address, int port, PrivateKey key)
        {
            return new Server(new TcpListener(new IPEndPoint(address, port)), key.InnerRSA);
        }
        /// <summary>
        /// Create a server where secure sessions are provided
        /// </summary>
        /// <param name="endpoint">IP endpoint</param>
        /// <param name="key">Private Key for Server</param>
        /// <returns>Server created (not Start()</returns>
        public static Server Create(IPEndPoint endpoint, PrivateKey key)
        {
            return new Server(new TcpListener(endpoint), key.InnerRSA);
        }
    }
}
