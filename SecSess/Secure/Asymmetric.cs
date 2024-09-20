using SecSess.Interface;
using SecSess.Key;
using System.Security.Cryptography;

namespace SecSess.Secure
{
    /// <summary>
    /// Custom asymmetric algorighm wrapper
    /// </summary>
    public class Asymmetric
    {
        /// <summary>
        /// Asymmetric algorithm that actually works
        /// </summary>
        public RSA? AsymmetricAlgorithm { get; private set; }

        /// <summary>
        /// Asymmetric algorithm to use
        /// </summary>
        public Algorithm.Asymmetric Algorithm { get; private set; }

        /// <summary>
        /// Create an asymmetric algorithm wrapper with the given key
        /// </summary>
        /// <param name="param"> Asymmetric algorithm parameter</param>
        /// <param name="algorithm"> Asymmetric algorithm to use</param>
        public Asymmetric(AsymmetricKeyBase param, Algorithm.Asymmetric algorithm)
        {
            Algorithm = algorithm;

            switch (algorithm)
            {
                case Secure.Algorithm.Asymmetric.None:
                    AsymmetricAlgorithm = null; 
                    break;
                case Secure.Algorithm.Asymmetric.RSA:
                    AsymmetricAlgorithm = RSA.Create(param.InnerRSA); 
                    break;
            }
        }
    }
}
