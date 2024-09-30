namespace Openus.SecSess.Transport.Option
{
    /// <summary>
    /// How to handle when error in reading
    /// </summary>
    public enum HandlingType
    {
        /// <summary>
        /// Occur error, throwing exception
        /// </summary>
        Ecexption = 1,
        /// <summary>
        /// Occur error, return empty array or null
        /// </summary>
        EmptyReturn = 2,
    }
}
