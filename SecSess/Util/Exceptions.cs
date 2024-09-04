using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecSess.Util
{
    /// <summary>
    /// Occurs when an initial secure session cannot be formed
    /// </summary>
    public class SecSessRefuesedException : Exception
    {
        public SecSessRefuesedException() : base("Failed to create a secure session.") { }
    }
}
