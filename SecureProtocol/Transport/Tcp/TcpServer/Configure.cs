using System.Net;

namespace Openus.SecureProtocol.Transport.Tcp
{
    /// <summary>
    /// TCP server with secure sessions
    /// </summary>
    public partial class TcpServer
    {
        /// <summary>
        /// Determining whether to enable session tickets used for reconnection, default 5 mins
        /// </summary>
        /// <param name="time">Ticket activation time, 0 is deactivated ticket system</param>
        /// <returns></returns>
        public TcpServer WithEnableTicket(TimeSpan time)
        {
            _enableTicketTime = time;
            return this;
        }

        /// <summary>
        /// Works a background thread that cleans tickets.
        /// Memory usage can be reduced, but CPU usage can be increased.
        /// </summary>
        /// <param name="interval"></param>
        /// <returns></returns>
        public TcpServer WithEnableTicketCleaner(TimeSpan interval) 
        {
            _useTicketCleaner = true;
            _ticketCleanerInterval = interval;
            return this;
        }

        /// <summary>
        /// Create a black list and block specific endpoints
        /// </summary>
        /// <param name="ep"></param>
        /// <returns></returns>
        public TcpServer WithBlackList(params IPEndPoint[] ep)
        {
            _blackList = ep.ToList();
            return this;
        }
    }
}
