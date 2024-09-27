using Openus.Net.SecSess.Secure.Algorithm;
using Openus.Net.SecSess.Secure.Wrapper;

namespace Openus.Net.SecSess.Key.Session
{
    /// <summary>
    /// Symmetric session key set(symmetric key, HMAC key) wrapping class
    /// </summary>
    public class KeySet
    {
        /// <summary>
        /// Symmetric key for session
        /// </summary>
        internal byte[] SymmetricKey { get; set; }
        /// <summary>
        /// HMAC key for session
        /// </summary>
        internal byte[] HMacKey { get; set; }

        /// <summary>
        /// Make instance
        /// </summary>
        /// <param name="symmetric">Symmetric key for session</param>
        /// <param name="hmac">Hmac key for session</param>
        /// <param name="set">Algorithm set to use</param>
        internal KeySet(byte[] symmetric, byte[] hmac, Set set)
        {
            if (symmetric.Length != Symmetric.KeySize(set.Symmetric) 
                || hmac.Length != Hash.HMacKeySize(set.Hash))
            {
                throw new ArgumentOutOfRangeException("Use invalid size key.");
            }

            SymmetricKey = symmetric;
            HMacKey = hmac;
        }
    }
}
