using Openus.SecureProtocol.Util;

namespace Openus.SecureProtocol.Transport.Option
{
    /// <summary>
    /// How to handle when error in reading
    /// </summary>
    public enum HandlingType
    {
        /// <summary>
        /// Occur error from reading, throwing exception
        /// </summary>
        Ecexption = 1,
        /// <summary>
        /// Occur error from reading, return null
        /// </summary>
        ReturnNull = 2,
        /// <summary>
        /// Ocuur error from reading, resume activities without any warning
        /// All read errors are automatically ignored and restarted method, 
        /// return value is never null.
        /// </summary>
        IgnoreLoop = 3,
    }

    ///// <summary>
    ///// Error occurring event handler
    ///// </summary>
    //internal static class Handler
    //{
    //    /// <summary>
    //    /// Handling function
    //    /// </summary>
    //    /// <typeparam name="T"></typeparam>
    //    /// <param name="type"></param>
    //    /// <param name="code"></param>
    //    /// <param name="task"></param>
    //    /// <returns></returns>
    //    /// <exception cref="SPException"></exception>
    //    internal static bool Handling<T>(HandlingType type, ExceptionCode code, Task? task = null) where T : class
    //    {
    //        switch (type) 
    //        {
    //            case HandlingType.Ecexption: throw new SPException(code);
    //                case HandlingType.ReturnNull: return null;

    //        }
    //    }
    //}
}
