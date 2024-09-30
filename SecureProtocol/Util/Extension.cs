using System.Text;

namespace Openus.SecureProtocol.Util
{
    /// <summary>
    /// A collection of extension methods required
    /// </summary>
    internal static class Extension
    {
        public static byte[] GetBytes(this string data)
        {
            return Encoding.UTF8.GetBytes(data);
        }

        public static string GetString(this byte[] data)
        {
            return Encoding.UTF8.GetString(data);
        }
    }
}
