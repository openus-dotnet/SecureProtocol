using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecSess.Tcp
{
    /// <summary>
    /// The type of client state to judge
    /// </summary>
    public enum StreamType
    {
        None = 0,
        Read = 1,
        Write = 2,
        Connect = 4,
        All = 7,
    }
}
