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
        internal byte[] SymmetricKey { get; private set; }
        /// <summary>
        /// HMAC key for session
        /// </summary>
        internal byte[] HmacKey { get; private set; }
        /// <summary>
        /// Algorithm set to use
        /// </summary>
        internal Set AlgorithmSet { get; private set; }

        /// <summary>
        /// Make instance
        /// </summary>
        /// <param name="symmetric">Symmetric key for session</param>
        /// <param name="hmac">Hmac key for session</param>
        /// <param name="set">Algorithm set to use</param>
        internal KeySet(byte[] symmetric, byte[] hmac, Set set)
        {
            if (symmetric.Length != Symmetric.KeySize(set.Symmetric) 
                || hmac.Length != Hash.HmacKeySize(set.Hash))
            {
                throw new ArgumentOutOfRangeException("Use invalid size key.");
            }

            SymmetricKey = symmetric;
            HmacKey = hmac;
            AlgorithmSet = set;
        }
    }
}
