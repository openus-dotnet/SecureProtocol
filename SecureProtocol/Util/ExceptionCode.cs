namespace Openus.SecureProtocol.Util
{
    /// <summary>
    /// Exception code enumable
    /// </summary>
    internal enum ExceptionCode
    {
        None,
        InvalidAsymmetric,
        InvalidCombination,
        InvalidSymmetric,
        EncryptError,
        DecryptError,
        InvalidHandlingType,
        InvalidNonce,
        InvalidHmac,
    }
}
