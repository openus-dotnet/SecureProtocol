using System.Text;

namespace Openus.SecureProtocol.Util
{
    /// <summary>
    /// A collection of extension methods required
    /// </summary>
    internal static class Extension
    {
        internal static byte[] GetBytes(this string data)
        {
            return Encoding.UTF8.GetBytes(data);
        }

        internal static string GetString(this byte[] data)
        {
            return Encoding.UTF8.GetString(data);
        }

        internal static string GetByteArrayString(this byte[] data) 
        {
            return "[ " + string.Join(", ", data) + " ]";
        }
    }
}
