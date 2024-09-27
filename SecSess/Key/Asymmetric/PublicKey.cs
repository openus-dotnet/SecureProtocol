using Openus.Net.SecSess.Key.Asymmetric.Interface;
using Openus.Net.SecSess.Secure.Algorithm;
using System.Security.Cryptography;

namespace Openus.Net.SecSess.Key.Asymmetric
{
    /// <summary>
    /// Public key warpper type
    /// </summary>
    public class PublicKey : BaseAsymmetricKey, IAsymmetricKey<PublicKey>
    {
        /// <summary>
        /// Create a public key
        /// </summary>
        /// <param name="algorithm">Asymmetric algorithm to use</param>
        /// <param name="parameters">Actual RSA parameters (without private key parameter)</param>
        internal PublicKey(AsymmetricType algorithm, object parameters)
        {
            Algorithm = algorithm;

            switch (algorithm)
            {
                case AsymmetricType.RSA:
                    InnerRSA = (RSAParameters)parameters;
                    break;
                default:
                    throw new ArgumentException("This algorithm can not use.");
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
                    result = rsa.ExportRSAPublicKey();
                    break;
                default:
                    throw new ArgumentException("Invalid algorithm to save");
            }

            using (BinaryWriter sw = new BinaryWriter(new FileStream(path, FileMode.OpenOrCreate)))
            {
                sw.Write(result);
            }
        }

        /// <summary>
        /// Load keys saved in binary format
        /// </summary>
        /// <param name="algorithm">Asymmetric algorithm to use</param>
        /// <param name="path">Path from load the key</param>
        /// <returns>Wrapped public key</returns>
        public static PublicKey Load(AsymmetricType algorithm, string path)
        {
            byte[] result;

            using (BinaryReader r = new BinaryReader(new FileStream(path, FileMode.Open, FileAccess.Read)))
            {
                result = r.ReadBytes((int)r.BaseStream.Length);
            }

            switch (algorithm)
            {
                case AsymmetricType.RSA:
                    RSA rsa = RSA.Create();
                    rsa.ImportRSAPublicKey(result, out int o1);
                    return new PublicKey(algorithm, rsa.ExportParameters(false));
                default:
                    throw new ArgumentException("Invalid algorithm to save");
            }
        }
    }
}
