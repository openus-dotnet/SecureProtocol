using System.Security.Cryptography;
using SecSess.Interface;
using SecSess.Secure.Algorithm;

namespace SecSess.Key
{
    /// <summary>
    /// Private key warpper type
    /// </summary>
    public class PrivateKey : AsymmetricKeyBase, IKeyPair<PrivateKey>
    {
        /// <summary>
        /// Create a private key
        /// </summary>
        /// <param name="algorithm">Asymmetric algorithm to use</param>
        /// <param name="parameters">Actual algorithm parameters (with private key parameter)</param>
        internal PrivateKey(Asymmetric algorithm, object parameters)
        {
            Algorithm = algorithm;

            switch (algorithm)
            {
                case Asymmetric.RSA:
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
                case Asymmetric.RSA:
                    RSA rsa = RSA.Create(InnerRSA);
                    result = rsa.ExportRSAPrivateKey();
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
        /// <returns>Wrapped private key</returns>
        public static PrivateKey Load(Asymmetric algorithm, string path)
        {
            byte[] result; 
            
            using (BinaryReader r = new BinaryReader(new FileStream(path, FileMode.Open, FileAccess.Read)))
            {
                result = r.ReadBytes((int)r.BaseStream.Length);
            }

            switch (algorithm)
            {
                case Asymmetric.RSA:
                    RSA rsa = RSA.Create();
                    rsa.ImportRSAPrivateKey(result, out int o1);
                    return new PrivateKey(algorithm, rsa.ExportParameters(true));
                default:
                    throw new ArgumentException("Invalid algorithm to save");
            }
        }
    }
}
