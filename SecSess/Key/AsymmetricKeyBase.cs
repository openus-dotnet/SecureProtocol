using Open.Net.SecSess.Secure.Algorithm;
using System.Security.Cryptography;

namespace Open.Net.SecSess.Key
{
    /// <summary>
    /// Abstract key base types for defining public/private key types
    /// </summary>
    public abstract class AsymmetricKeyBase
    {
        /// <summary>
        /// Asymmetric algorithm to use
        /// </summary>
        internal Asymmetric Algorithm { get; set; }
        /// <summary>
        /// RSA parameters for actual RSA encryption
        /// </summary>
        internal RSAParameters InnerRSA { get; set; }
    }
}
