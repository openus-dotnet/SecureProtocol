namespace Openus.Net.SecSess.Util
{
    /// <summary>
    /// Exception code enumable
    /// </summary>
    public enum ExceptionCode
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
