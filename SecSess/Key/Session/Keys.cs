using Openus.Net.SecSess.Secure.Algorithm;
using Openus.Net.SecSess.Secure.Wrapper;

namespace Openus.Net.SecSess.Key.Session
{
    public class Keys
    {
        internal byte[] SymmetricKey { get; set; }
        internal byte[] HMacKey { get; set; }

        internal Keys(byte[] symmetric, byte[] hmac, Set set)
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
