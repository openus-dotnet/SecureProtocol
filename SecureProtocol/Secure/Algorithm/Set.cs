using W = Openus.SecureProtocol.Secure.Wrapper;

namespace Openus.SecureProtocol.Secure.Algorithm
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

        /// <summary>
        /// In connect session, minimum packet size(Asymmetric || Ticket..)
        /// </summary>
        /// <returns></returns>
        internal int GetMinimumConnectPacketSize()
        {
            return Math.Max(GetOnlyTicketPacketSize(this) + W.Symmetric.BlockSize(Symmetric), W.Asymmetric.BlockSize(Asymmetric));
        }

        /// <summary>
        /// Get ticket packet size without IV
        /// </summary>
        /// <param name="set">Algorithm set to use</param>
        /// <returns></returns>
        internal static int GetOnlyTicketPacketSize(Set set)
        {
            int normal = 4 + W.Symmetric.KeySize(set.Symmetric) + W.Hash.HmacKeySize(set.Hash) + W.Symmetric.BlockSize(set.Symmetric);

            return (normal / W.Symmetric.KeySize(set.Symmetric) + (normal % W.Symmetric.KeySize(set.Symmetric) == 0 ? 0 : 1))
                * W.Symmetric.KeySize(set.Symmetric);
        }
    }
}
