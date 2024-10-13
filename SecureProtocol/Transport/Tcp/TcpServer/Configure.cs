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
        /// <param name="time">Ticket activation time, 0 temporarily deactivated</param>
        /// <returns></returns>
        public TcpServer WithEnableTicket(TimeSpan time)
        {
            _enableTicketTime = time;

            return this;
        }
    }
}
