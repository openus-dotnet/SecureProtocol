namespace Openus.SecureProtocol.Util
{
    /// <summary>
    /// Secure protocol module custom exceptions
    /// </summary>
    public class SecProtoException : Exception
    {
        /// <summary>
        /// Generate exception with code
        /// </summary>
        /// <param name="code">Exception code</param>
        /// <param name="values">Other information value</param>
        internal SecProtoException(ExceptionCode code, params string[] values) : base(GetMessage(code) + GetInfo(values)) { }

        /// <summary>
        /// Only message secure protocol exception
        /// </summary>
        /// <param name="message">Message to except</param>
        public SecProtoException(string message) : base(message) { }

        /// <summary>
        /// Get more informations for exception
        /// </summary>
        /// <param name="values">Information parameter</param>
        /// <returns></returns>
        private static string GetInfo(string[] values)
        {
            if (values != null && values.Length != 0)
            {
                string result = "(";

                foreach (string value in values)
                {
                    result += value + ", ";
                }

                return result + ")";
            }

            return "";
        }

        /// <summary>
        /// Return message from exception code
        /// </summary>
        /// <param name="code">Exception code</param>
        /// <returns>Exception message</returns>
        private static string GetMessage(ExceptionCode code)
        {
            switch (code)
            {
                case ExceptionCode.None: return "Unknown";
                case ExceptionCode.InvalidAsymmetric: return "Invalid asymmetric algorithm";
                case ExceptionCode.InvalidCombination: return "Invalid combinate between parameters";
                case ExceptionCode.InvalidSymmetric: return "Invalid symmetric algorithm";
                case ExceptionCode.EncryptError: return "Occur error in data encryption";
                case ExceptionCode.DecryptError: return "Occur error in data decryption";
                case ExceptionCode.InvalidHandlingType: return "Invalid handling type";
                case ExceptionCode.InvalidNonce: return "Invalid received nonce";
                case ExceptionCode.InvalidHmac: return "IHMAC authentication is failed";
                case ExceptionCode.InvalidConnection: return "The first connection is can not used ReConnect()";
                case ExceptionCode.InvalidTicket: return "Invalid session ticket";
                default: return "Unknown exception";
            }
        }
    }
}
