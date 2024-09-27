namespace Openus.Net.SecSess.Transport.Option
{
    /// <summary>
    /// The type of client state to judge
    /// </summary>
    public enum StreamState
    {
        None = 0,
        CanRead = 1,
        CanWrite = 2,
        Connected = 4,
        All = 7,
    }
}
