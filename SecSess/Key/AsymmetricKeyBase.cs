using System.Security.Cryptography;

namespace SecSess.Key
{
    /// <summary>
    /// Abstract key base types for defining public/private key types
    /// </summary>
    public abstract class AsymmetricKeyBase
    {
        /// <summary>
        /// RSA parameters for actual RSA encryption
        /// </summary>
        internal RSAParameters InnerRSA { get; set; }
    }
}
