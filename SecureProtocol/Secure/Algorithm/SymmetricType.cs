namespace Openus.SecureProtocol.Secure.Algorithm
{
    /// <summary>
    /// Symmetric key algorithm to use
    /// </summary>
    public enum SymmetricType
    {
        /// <summary>
        /// None symmetric algorithm
        /// </summary>
        None = 0,
        /// <summary>
        /// DES symmetric algorithm
        /// </summary>
        DES = 1,
        /// <summary>
        /// 3-DES symmetric algorithm
        /// </summary>
        TripleDES = 2,
        /// <summary>
        /// AES symmetric algorithm
        /// </summary>
        AES = 3,
    }
}
