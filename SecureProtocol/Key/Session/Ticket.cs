namespace Openus.SecureProtocol.Key.Session
{
    /// <summary>
    /// Ticket for TCP session fast re-connection
    /// </summary>
    public class Ticket
    {
        /// <summary>
        /// Ticket's packet bytes with IV
        /// </summary>
        internal byte[] TicketPacket { get; set; }

        /// <summary>
        /// Generate ticket wrapping class
        /// </summary>
        /// <param name="ticketPacket">Ticket's packet bytes with IV</param>
        internal Ticket(byte[] ticketPacket)
        {
            TicketPacket = ticketPacket;
        }
    }
}
