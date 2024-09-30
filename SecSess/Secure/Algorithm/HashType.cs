namespace Openus.SecSess.Secure.Algorithm
{
    /// <summary>
    /// Hash algorithm to use
    /// </summary>
    public enum HashType
    {
        /// <summary>
        /// Do not use hash
        /// </summary>
        None = 0,
        /// <summary>
        /// SHA-1 and HMAC-1
        /// </summary>
        SHA1 = 1,
        /// <summary>
        /// SHA-2 256 and HMAC-2 256
        /// </summary>
        SHA256 = 2,
        /// <summary>
        /// SHA-2 384 and HMAC-2 384
        /// </summary>
        SHA384 = 3,
        /// <summary>
        /// SHA-2 512 and HMAC-2 512
        /// </summary>
        SHA512 = 4,
        /// <summary>
        /// SHA-3 256 and HMAC-3 256
        /// </summary>
        SHA3_256 = 5,
        /// <summary>
        /// SHA-3 384 and HMAC-3 384
        /// </summary>
        SHA3_384 = 6,
        /// <summary>
        /// SHA-3 512 and HMAC-3 512
        /// </summary>
        SHA3_512 = 7,
    }
}
