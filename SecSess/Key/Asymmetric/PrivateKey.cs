using Openus.Net.SecSess.Key.Asymmetric.Interface;
using Openus.Net.SecSess.Secure.Algorithm;
using Openus.Net.SecSess.Util;
using System.Security.Cryptography;

namespace Openus.Net.SecSess.Key.Asymmetric
{
    /// <summary>
    /// Private key warpper type
    /// </summary>
    public class PrivateKey : BaseAsymmetricKey, IAsymmetricKey<PrivateKey>
    {
        /// <summary>
        /// Create a private key
        /// </summary>
        /// <param name="algorithm">Asymmetric algorithm to use</param>
        /// <param name="parameters">Actual algorithm parameters (with private key parameter)</param>
        internal PrivateKey(AsymmetricType algorithm, object parameters)
        {
            Algorithm = algorithm;

            switch (algorithm)
            {
                case AsymmetricType.RSA:
                    InnerRSA = (RSAParameters)parameters;

                    break;
                default:
                    throw new SecSessException(ExceptionCode.InvalidAsymmetric);
            }
        }

        /// <summary>
        /// Save the key in binary format
        /// </summary>
        /// <param name="path">Path to save the key</param>
        public void Save(string path)
        {
            byte[] result;

            switch (Algorithm)
            {
                case AsymmetricType.RSA:
                    RSA rsa = RSA.Create(InnerRSA);
                    result = rsa.ExportRSAPrivateKey();

                    break;
                default:
                    throw new SecSessException(ExceptionCode.InvalidAsymmetric);
            }

            using (StreamWriter sw = new StreamWriter(path))
            {
                sw.Write(Convert.ToBase64String(result));
            }
        }

        /// <summary>
        /// Load keys saved in binary format
        /// </summary>
        /// <param name="algorithm">Asymmetric algorithm to use</param>
        /// <param name="path">Path from load the key</param>
        /// <returns>Wrapped private key</returns>
        public static PrivateKey Load(AsymmetricType algorithm, string path)
        {
            byte[] result;

            using (StreamReader sr = new StreamReader(path))
            {
                result = Convert.FromBase64String(sr.ReadToEnd());
            }

            switch (algorithm)
            {
                case AsymmetricType.RSA:
                    RSA rsa = RSA.Create();
                    rsa.ImportRSAPrivateKey(result, out int o1);

                    return new PrivateKey(algorithm, rsa.ExportParameters(true));
                default:
                    throw new SecSessException(ExceptionCode.InvalidAsymmetric);
            }
        }
    }
}
