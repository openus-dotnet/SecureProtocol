using System.Net.Sockets;
using Openus.SecureProtocol.Secure.Wrapper;
using Openus.SecureProtocol.Secure.Algorithm;
using System.Net;

namespace Openus.SecureProtocol.Transport.Tcp
{
    /// <summary>
    /// TCP server with secure sessions
    /// </summary>
    public partial class TcpServer
    {
        /// <summary>
        /// Clients accepted by the server side
        /// </summary>
        public class Client : BaseTcp
        {
            /// <summary>
            /// Create a server side client
            /// </summary>
            /// <param name="client">Client that actually works</param>
            /// <param name="symmetricKey">The AES key used to communicate with this client</param>
            /// <param name="hmacKey">The HMAC key used to communicate with this client</param>
            /// <param name="set">Algorithm set to use</param>
            internal Client(System.Net.Sockets.TcpClient client, byte[] symmetricKey, byte[] hmacKey, Set set)
                : base(client, set, symmetricKey, hmacKey) { }
        }

        /// <summary>
        /// Ticket for session re-connection
        /// </summary>
        private class Ticket
        {
            /// <summary>
            /// Last used nonce
            /// </summary>
            internal static int MaxNonce = 1;

            /// <summary>
            /// Ticket nonce
            /// </summary>
            internal int Nonce;
            /// <summary>
            /// Session's symmetric key
            /// </summary>
            internal byte[] SymmetricKey;
            /// <summary>
            /// Session's HMAC key
            /// </summary>
            internal byte[] HmacKey;
            /// <summary>
            /// Ticket's IV
            /// </summary>
            internal byte[] IV;
            /// <summary>
            /// Ticket's generated time
            /// </summary>
            internal DateTime Timestamp;

            /// <summary>
            /// Create ticket for session, can set nonce
            /// </summary>
            /// <param name="nonce">Used nonce</param>
            /// <param name="symmetric">Session's symmetric key</param>
            /// <param name="hmac">Session's HMAC key</param>
            /// <param name="iv">IV for symmetric encryption</param>
            public Ticket(int nonce, byte[] symmetric, byte[] hmac, byte[] iv)
            {
                Nonce = nonce;
                SymmetricKey = symmetric;
                HmacKey = hmac;
                IV = iv;
                Timestamp = DateTime.UtcNow;
            }

            /// <summary>
            /// Create ticket for session
            /// </summary>
            /// <param name="symmetric">Session's symmetric key</param>
            /// <param name="hmac">Session's HMAC key</param>
            /// <param name="iv">IV for symmetric encryption</param>
            public Ticket(byte[] symmetric, byte[] hmac, byte[] iv) : this(MaxNonce++, symmetric, hmac, iv) { }

            /// <summary>
            /// Ticket to bytes
            /// </summary>
            /// <returns></returns>
            public byte[] ToBytes()
            {
                byte[] result = new byte[4 + SymmetricKey.Length + HmacKey.Length + IV.Length];

                Buffer.BlockCopy(BitConverter.GetBytes(Nonce), 0, result, 0, 4);
                Buffer.BlockCopy(SymmetricKey, 0, result, 4, SymmetricKey.Length);
                Buffer.BlockCopy(HmacKey, 0, result, 4 + SymmetricKey.Length, HmacKey.Length);
                Buffer.BlockCopy(IV, 0, result, 4 + SymmetricKey.Length + HmacKey.Length, IV.Length);

                return result;
            }

            /// <summary>
            /// Get ticket from bytes
            /// </summary>
            /// <param name="bytes"></param>
            /// <param name="set">Using algorithm set</param>
            /// <returns></returns>
            public static Ticket ToTicket(byte[] bytes, Set set)
            {
                int toSym = 4 + Symmetric.KeySize(set.Symmetric);
                int toHmac = toSym + Hash.HmacKeySize(set.Hash);
                int toIV = toHmac + Symmetric.BlockSize(set.Symmetric);

                Ticket ticket = new Ticket
                (
                    BitConverter.ToInt32(bytes[0..4]),
                    bytes[4..toSym],
                    bytes[toSym..toHmac],
                    bytes[toHmac..toIV]
                );

                return ticket;
            }
        }

        /// <summary>
        /// A TCP listener that actually works
        /// </summary>
        private TcpListener _listener;
        /// <summary>
        /// Secure client list
        /// </summary>
        private List<Client> _clients;
        /// <summary>
        /// Asymmetric algorithm with private key for server
        /// </summary>
        private Asymmetric _asymmetric;
        /// <summary>
        /// Algorithm set to use
        /// </summary>
        private Set _set;
        /// <summary>
        /// Only used server symmetric wrapper for session ticket 
        /// </summary>
        private Symmetric _ticketSymmetric;
        /// <summary>
        /// Session ticket for re-connect
        /// </summary>
        private List<Ticket> _tickets;
        /// <summary>
        /// Enable session ticket time
        /// </summary>
        private TimeSpan _enableTicketTime;
        /// <summary>
        /// Black list specific IP end point
        /// </summary>
        private List<IPEndPoint> _blackList;
        /// <summary>
        /// Server is listening now
        /// </summary>
        public bool IsListening { get; private set; }
        /// <summary>
        /// Server using ticket cleaner
        /// </summary>
        private bool _useTicketCleaner;
        /// <summary>
        /// Ticket cleaner interval
        /// </summary>
        private TimeSpan _ticketCleanerInterval;
    }
}
