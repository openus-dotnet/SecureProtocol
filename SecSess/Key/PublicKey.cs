using System.Security.Cryptography;

namespace SecSess.Key
{
    /// <summary>
    /// Public key warpper type
    /// </summary>
    public class PublicKey : RSAKeyBase
    {
        /// <summary>
        /// Create a public key
        /// </summary>
        /// <param name="parameters">Actual RSA parameters (without private key parameter)</param>
        internal PublicKey(RSAParameters parameters)
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

            using (BinaryWriter w = new BinaryWriter(new FileStream(path, FileMode.OpenOrCreate, FileAccess.Write)))
            {
                w.Write(rsa.ExportRSAPublicKey());
            }
        }

        /// <summary>
        /// Load keys saved in binary format
        /// </summary>
        /// <param name="path">Path from load the key</param>
        /// <returns>Wrapped public key</returns>
        public static PublicKey Load(string path)
        {
            RSA rsa = RSA.Create();

            using (BinaryReader r = new BinaryReader(new FileStream(path, FileMode.Open, FileAccess.Read)))
            {
                rsa.ImportRSAPublicKey(r.ReadBytes((int)r.BaseStream.Length), out int o);
            }

            PublicKey result = new PublicKey(rsa.ExportParameters(false));

            return result;
        }
    }
}
