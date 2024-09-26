namespace Openus.Net.SecSess.Secure.Algorithm
{
    /// <summary>
    /// Algorithm set to use
    /// </summary>
    public struct Set
    {
        /// <summary>
        /// Asymmetric algorithm to use
        /// </summary>
        public required AsymmetricType Asymmetric { get; set; }

        /// <summary>
        /// Symmetric algorithm to use
        /// </summary>
        public required SymmetricType Symmetric { get; set; }

        /// <summary>
        /// Hash algorithm to use
        /// </summary>
        public required HashType Hash { get; set; }

        /// <summary>
        /// Return all none algorithms set
        /// </summary>
        public static Set NoneSet => new Set()
        {
            Symmetric = SymmetricType.None,
            Hash = HashType.None,
            Asymmetric = AsymmetricType.None,
        };
    }
}
