using Openus.SecureProtocol.Key.Asymmetric;
using Openus.SecureProtocol.Util;
using Openus.SecureProtocol.Secure.Wrapper;
using Openus.SecureProtocol.Secure.Algorithm;
using Openus.SecureProtocol.Transport.Option;
using System.Net;
using System.Security.Cryptography;
using Raw = System.Net.Sockets;

namespace Openus.SecureProtocol.Transport.Tcp
{
    /// <summary>
    /// TCP server with secure sessions
    /// </summary>
    public partial class TcpServer
    {
        /// <summary>
        /// General constructor for server
        /// </summary>
        /// <param name="listener">A TCP listener that actually works</param>
        /// <param name="parameters">Asymmetric key base with private key for server</param>
        /// <param name="set">Algorithm set to use</param>
        private TcpServer(Raw.TcpListener listener, BaseAsymmetricKey? parameters, Set set)
        {
            _listener = listener;
            _clients = new List<Client>();
            _asymmetric = new Asymmetric(parameters, set.Asymmetric);
            _set = set;

            byte[] ticketKey = new byte[Symmetric.KeySize(set.Symmetric)];
            RandomNumberGenerator.Fill(ticketKey);

            _ticketSymmetric = new Symmetric(ticketKey, set.Symmetric);
            _tickets = new List<Ticket>();
            _enableTicketTime = TimeSpan.FromMinutes(5);
            _blackList = new List<IPEndPoint>();
            _useTicketCleaner = false;
            _ticketCleanerInterval = TimeSpan.Zero;

            IsListening = false;
        }

        /// <summary>
        /// Create a server without secure session
        /// </summary>
        /// <param name="endPoint"></param>
        /// <returns>Server created (already not Start())</returns>
        public static TcpServer Craete(IPEndPoint endPoint)
        {
            return new TcpServer(new Raw.TcpListener(endPoint), null, Set.NoneSet);
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
            return new TcpServer(new Raw.TcpListener(endPoint), key, set);
        }

        /// <summary>
        /// Start TCP listener
        /// </summary>
        public void Start()
        {
            _listener.Start();
            IsListening = true;

            if (_useTicketCleaner == true)
            {
                if (_ticketCleanerInterval == TimeSpan.Zero)
                {
                    throw new SPException(ExceptionCode.InvalidTimeSpan);
                }

                Task.Run(async () =>
                {
                    while (true)
                    {
                        try
                        {
                            while (IsListening == true)
                            {
                                lock (_tickets)
                                {
                                    _tickets.RemoveAll(x => DateTime.UtcNow - x.Timestamp > _enableTicketTime);
                                }

                                await Task.Delay(_ticketCleanerInterval);
                            }

                            lock (_tickets)
                            {
                                _tickets.Clear();
                            }
                        }
                        catch
                        {
                            continue;
                        }
                    }
                });
            }
        }

        /// <summary>
        /// Stop the TCP listener
        /// </summary>
        public void Stop()
        {
            _listener.Stop();
            _listener.Dispose();
            IsListening = false;
        }

        /// <summary>
        /// Accept a pending connection request
        /// </summary>
        /// <param name="type">How to handle when error</param>
        public Client? AcceptClient(HandlingType type = HandlingType.Ecexption)
        {AcceptClient:
            Raw.TcpClient client = _listener.AcceptTcpClient();

            if (_blackList.Contains(client.Client.RemoteEndPoint) == true)
            {
                switch (type)
                {
                    case HandlingType.Ecexption:
                        throw new SPException(ExceptionCode.BlackList);
                    case HandlingType.ReturnNull:
                        return null;
                    case HandlingType.IgnoreLoop:
                        goto AcceptClient;
                    default:
                        throw new SPException(ExceptionCode.InvalidHandlingType);
                }
            }

            while (client.Connected == false || client.GetStream().CanRead == false) ;

            if (_set.Symmetric != SymmetricType.None)
            {
                byte[] buffer = new byte[_set.GetMinimumConnectPacketSize()];

                int s = 0;
                while (s < buffer.Length)
                    s += client.GetStream().Read(buffer, s, buffer.Length - s);

                byte[]? concatAsym = _asymmetric.Decrypt(buffer);

                int ticketSize = Set.GetOnlyTicketPacketSize(_set);
                byte[]? concatSym = _ticketSymmetric.Decrypt(
                    buffer[Symmetric.BlockSize(_set.Symmetric)..(ticketSize + Symmetric.BlockSize(_set.Symmetric))], 
                        buffer[0..Symmetric.BlockSize(_set.Symmetric)]
                );

                if (concatAsym == null && concatSym == null)
                {
                    client.Close();

                    switch (type)
                    {
                        case HandlingType.Ecexption:
                            throw new SPException(ExceptionCode.DecryptError);
                        case HandlingType.ReturnNull:
                            return null;
                        case HandlingType.IgnoreLoop:
                            goto AcceptClient;
                        default:
                            throw new SPException(ExceptionCode.InvalidHandlingType);
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

                    lock (_tickets)
                        _tickets.Add(ticket);

                    byte[]? ticketPacket = _ticketSymmetric.Encrypt(ticket.ToBytes(), iv);

                    if (ticketPacket == null)
                    {
                        client.Close();

                        throw new SPException(ExceptionCode.EncryptError);
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
                    Ticket? find = null;

                    lock (_tickets)
                        find = _tickets.FirstOrDefault(x => x.ToBytes().SequenceEqual(ticket.ToBytes()));

                    if (find == null)
                    {
                        client.Close();

                        switch (type)
                        {
                            case HandlingType.Ecexption:
                                throw new SPException(ExceptionCode.InvalidTicket);
                            case HandlingType.ReturnNull:
                                return null;
                            case HandlingType.IgnoreLoop:
                                goto AcceptClient;
                            default:
                                throw new SPException(ExceptionCode.InvalidHandlingType);
                        }
                    }
                    else
                    {
                        lock (_tickets)
                            _tickets.Remove(find);

                        TimeSpan to = DateTime.UtcNow - find.Timestamp;

                        if (to > _enableTicketTime)
                        {
                            switch (type)
                            {
                                case HandlingType.Ecexption:
                                    throw new SPException(ExceptionCode.InvalidTicket);
                                case HandlingType.ReturnNull:
                                    return null;
                                case HandlingType.IgnoreLoop:
                                    goto AcceptClient;
                                default:
                                    throw new SPException(ExceptionCode.InvalidHandlingType);
                            }
                        }
                    }

                    Client result = new Client(client, ticket.SymmetricKey, ticket.HmacKey, _set); 
                    
                    _clients.Add(result);

                    while (client.GetStream().CanWrite == false) ;

                    result.Write(Hash.HashData(_set.Hash, buffer));

                    byte[] iv = new byte[Symmetric.BlockSize(_set.Symmetric)];
                    RandomNumberGenerator.Fill(iv);

                    Ticket reticket = new Ticket(ticket.SymmetricKey, ticket.HmacKey, iv);

                    lock (_tickets)
                        _tickets.Add(reticket);

                    byte[]? ticketPacket = _ticketSymmetric.Encrypt(reticket.ToBytes(), iv);

                    if (ticketPacket == null)
                    {
                        client.Close();

                        throw new SPException(ExceptionCode.EncryptError);
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

                    throw new SPException(ExceptionCode.None);
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

                throw new SPException(ExceptionCode.InvalidCombination);
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
