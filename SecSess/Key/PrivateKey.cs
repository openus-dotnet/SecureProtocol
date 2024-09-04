using System.Security.Cryptography;

namespace SecSess.Key
{
    /// <summary>
    /// Private key warpper type
    /// </summary>
    public class PrivateKey : RSAKeyBase
    {
        /// <summary>
        /// Create a private key
        /// </summary>
        /// <param name="parameters">Actual RSA parameters (with private key parameter)</param>
        internal PrivateKey(RSAParameters parameters)
        {
            InnerRSA = parameters;
        }

        /// <summary>
        /// Save the key in binary format
        /// </summary>
        /// <param name="path">Path to save the key</param>
        public void Save(string path)
        {
            RSA rsa = RSA.Create(InnerRSA);

            using (BinaryWriter sw = new BinaryWriter(new FileStream(path, FileMode.OpenOrCreate)))
            {
                sw.Write(rsa.ExportRSAPrivateKey());
            }
        }

        /// <summary>
        /// Load keys saved in binary format
        /// </summary>
        /// <param name="path">Path from load the key</param>
        /// <returns>Wrapped private key</returns>
        public static PrivateKey Load(string path)
        {
            RSA rsa = RSA.Create();

            using (BinaryReader r = new BinaryReader(new FileStream(path, FileMode.Open, FileAccess.Read)))
            {
                rsa.ImportRSAPrivateKey(r.ReadBytes((int)r.BaseStream.Length), out int o);
            }

            PrivateKey result = new PrivateKey(rsa.ExportParameters(true));

            return result;
        }
    }
}
