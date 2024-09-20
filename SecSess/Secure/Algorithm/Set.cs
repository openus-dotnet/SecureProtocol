using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecSess.Secure.Algorithm
{
    /// <summary>
    /// Algorithm set to use
    /// </summary>
    public struct Set
    {
        /// <summary>
        /// Asymmetric algorithm to use
        /// </summary>
        public required Asymmetric Asymmetric { get; set; }

        /// <summary>
        /// Symmetric algorithm to use
        /// </summary>
        public required Symmetric Symmetric { get; set; }

        /// <summary>
        /// Hash algorithm to use
        /// </summary>
        public required Hash Hash { get; set; }
    }
}
