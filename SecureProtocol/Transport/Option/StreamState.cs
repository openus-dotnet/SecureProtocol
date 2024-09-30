namespace Openus.SecureProtocol.Transport.Option
{
    /// <summary>
    /// The type of client state to judge
    /// </summary>
    public enum StreamState
    {
        /// <summary>
        /// Do not check stream state
        /// </summary>
        None = 0,
        /// <summary>
        /// Check to can read
        /// </summary>
        CanRead = 1,
        /// <summary>
        /// Check to can write
        /// </summary>
        CanWrite = 2,
        /// <summary>
        /// Check to is connected TCP
        /// </summary>
        Connected = 4,
        /// <summary>
        /// Check all state
        /// </summary>
        All = 7,
    }
}
