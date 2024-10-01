using System.Net.Sockets;
using System.Net;
using Openus.SecureProtocol.Key.Asymmetric;
using Openus.SecureProtocol.Util;
using Openus.SecureProtocol.Secure.Wrapper;
using Openus.SecureProtocol.Secure.Algorithm;
using Openus.SecureProtocol.Transport.Option;
using System.Security.Cryptography;
using System.Text.Json;
using Openus.SecureProtocol.Key.Asymmetric.Interface;

namespace Openus.SecureProtocol.Transport.Tcp
{
    /// <summary>
    /// TCP server with secure sessions
    /// </summary>
    public class TcpServer
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
            }

            /// <summary>
            /// Create ticket for session
            /// </summary>
            /// <param name="symmetric">Session's symmetric key</param>
            /// <param name="hmac">Session's HMAC key</param>
            /// <param name="iv">IV for symmetric encryption</param>
            public Ticket(byte[] symmetric, byte[] hmac, byte[] iv)
            {
                Nonce = MaxNonce++;
                SymmetricKey = symmetric;
                HmacKey = hmac;
                IV = iv;
            }

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
        /// General constructor for server
        /// </summary>
        /// <param name="listener">A TCP listener that actually works</param>
        /// <param name="parameters">Asymmetric key base with private key for server</param>
        /// <param name="set">Algorithm set to use</param>
        private TcpServer(TcpListener listener, BaseAsymmetricKey? parameters, Set set)
        {
            _listener = listener;
            _clients = new List<Client>();
            _asymmetric = new Asymmetric(parameters, set.Asymmetric);
            _set = set;

            byte[] ticketKey = new byte[Symmetric.KeySize(set.Symmetric)];
            RandomNumberGenerator.Fill(ticketKey);

            _ticketSymmetric = new Symmetric(ticketKey, set.Symmetric);
            _tickets = new List<Ticket>();
        }

        /// <summary>
        /// Create a server without secure session
        /// </summary>
        /// <param name="endPoint"></param>
        /// <returns>Server created (already not Start())</returns>
        public static TcpServer Craete(IPEndPoint endPoint)
        {
            return new TcpServer(new TcpListener(endPoint), null, Set.NoneSet);
        }

        /// <summary>
        /// Create a server where secure session is provided
        /// </summary>
        /// <param name="endPoint">IP end point</param>
        /// <param name="key">Private key for server</param>
        /// <param name="set">Algorithm set to use</param>
        /// <returns>Server created (already not Start())</returns>
        public static TcpServer Create(IPEndPoint endPoint, PrivateKey? key, Set set)
        {
            return new TcpServer(new TcpListener(endPoint), key, set);
        }

        /// <summary>
        /// Start TCP listener
        /// </summary>
        public void Start()
        {
            _listener.Start();
        }

        /// <summary>
        /// Stop the TCP listener
        /// </summary>
        public void Stop()
        {
            _listener.Stop();
            _listener.Dispose();
        }

        /// <summary>
        /// Accept a pending connection request
        /// </summary>
        /// <param name="type">How to handle when error</param>
        public Client? AcceptClient(HandlingType type = HandlingType.Ecexption)
        {
            System.Net.Sockets.TcpClient client = _listener.AcceptTcpClient();

            while (client.Connected == false || client.GetStream().CanRead == false) ;

            if (_set.Symmetric != SymmetricType.None)
            {
                byte[] buffer = new byte[_set.GetMinimumConnectPacketSize()];

                int s = 0;
                while (s < buffer.Length)
                    s += client.GetStream().Read(buffer, s, buffer.Length - s);

                byte[]? concatAsym = _asymmetric.Decrypt(buffer);

                int ticketSize = Set.GetOnlyTicketPacketSize(_set);
                byte[]? concatSym = _ticketSymmetric.Decrypt(buffer
                [
                    Symmetric.BlockSize(_set.Symmetric)..(ticketSize + Symmetric.BlockSize(_set.Symmetric))], 
                    buffer[0..Symmetric.BlockSize(_set.Symmetric)
                ]);

                if (concatAsym == null && concatSym == null)
                {
                    client.Close();

                    switch (type)
                    {
                        case HandlingType.Ecexption:
                            throw new SecProtoException(ExceptionCode.DecryptError);
                        case HandlingType.EmptyReturn:
                            return null;
                        default:
                            throw new SecProtoException(ExceptionCode.InvalidHandlingType);
                    }
                }
                if (concatAsym != null)
                {
                    byte[] symmetricKey = concatAsym[0..Symmetric.KeySize(_set.Symmetric)];
                    byte[] hmacKey = concatAsym[Symmetric.KeySize(_set.Symmetric)..(Symmetric.KeySize(_set.Symmetric) + Hash.HmacKeySize(_set.Hash))];

                    Client result = new Client(client, symmetricKey, hmacKey, _set);
                    _clients.Add(result);

                    while (client.GetStream().CanWrite == false) ;

                    result.Write(Hash.HashData(_set.Hash, concatAsym[0..(Symmetric.KeySize(_set.Symmetric) + Hash.HmacKeySize(_set.Hash))]));

                    byte[] iv = new byte[Symmetric.BlockSize(_set.Symmetric)];
                    RandomNumberGenerator.Fill(iv);

                    Ticket ticket = new Ticket(symmetricKey, hmacKey, iv);
                    _tickets.Add(ticket);

                    byte[]? ticketPacket = _ticketSymmetric.Encrypt(ticket.ToBytes(), iv);

                    if (ticketPacket == null)
                    {
                        client.Close();

                        throw new SecProtoException(ExceptionCode.EncryptError);
                    }

                    byte[] ticketWithIV = new byte[Symmetric.BlockSize(_set.Symmetric) + ticketPacket.Length];

                    Buffer.BlockCopy(iv, 0, ticketWithIV, 0, iv.Length);
                    Buffer.BlockCopy(ticketPacket, 0, ticketWithIV, iv.Length, ticketPacket.Length);

                    result.Write(ticketWithIV);

                    return result;
                }
                else if (concatSym != null)
                {
                    Ticket ticket = Ticket.ToTicket(concatSym, _set);
                    Ticket? find = _tickets.FirstOrDefault(x => x.ToBytes().SequenceEqual(ticket.ToBytes()));

                    if (find == null)
                    {
                        client.Close();

                        switch (type)
                        {
                            case HandlingType.Ecexption:
                                throw new SecProtoException(ExceptionCode.InvalidTicket);
                            case HandlingType.EmptyReturn:
                                return null;
                            default:
                                throw new SecProtoException(ExceptionCode.InvalidHandlingType);
                        }
                    }
                    else
                    {
                        _tickets.Remove(find);
                    }

                    Client result = new Client(client, ticket.SymmetricKey, ticket.HmacKey, _set); 
                    
                    _clients.Add(result);

                    while (client.GetStream().CanWrite == false) ;

                    result.Write(Hash.HashData(_set.Hash, buffer));

                    byte[] iv = new byte[Symmetric.BlockSize(_set.Symmetric)];
                    RandomNumberGenerator.Fill(iv);

                    Ticket reticket = new Ticket(ticket.SymmetricKey, ticket.HmacKey, iv);
                    _tickets.Add(reticket);

                    byte[]? ticketPacket = _ticketSymmetric.Encrypt(reticket.ToBytes(), iv);

                    if (ticketPacket == null)
                    {
                        client.Close();

                        throw new SecProtoException(ExceptionCode.EncryptError);
                    }

                    byte[] ticketWithIV = new byte[Symmetric.BlockSize(_set.Symmetric) + ticketPacket.Length];

                    Buffer.BlockCopy(iv, 0, ticketWithIV, 0, iv.Length);
                    Buffer.BlockCopy(ticketPacket, 0, ticketWithIV, iv.Length, ticketPacket.Length);

                    result.Write(ticketWithIV);

                    return result;
                }
                else
                {
                    client.Close();

                    throw new SecProtoException(ExceptionCode.None);
                }
            }
            else if (_set.Symmetric == SymmetricType.None)
            {
                Client result = new Client(client, Array.Empty<byte>(), Array.Empty<byte>(), _set);
                _clients.Add(result);

                return result;
            }
            else
            {
                client.Close();

                throw new SecProtoException(ExceptionCode.InvalidCombination);
            }
        }


        /// <summary>
        /// Accept a pending connection request
        /// </summary>
        /// <param name="type">How to handle when error</param>
        public async Task<Client?> AcceptClientAsync(HandlingType type = HandlingType.Ecexption)
        {
            return await Task.Run(() => AcceptClient(type));
        }
    }
}
