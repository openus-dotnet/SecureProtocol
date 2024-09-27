﻿using Openus.Net.SecSess.Secure.Algorithm;
using System.Security.Cryptography;

namespace Openus.Net.SecSess.Key.Asymmetric
{
    /// <summary>
    /// Abstract key base types for defining public/private key types
    /// </summary>
    public abstract class BaseAsymmetricKey
    {
        /// <summary>
        /// Asymmetric algorithm to use
        /// </summary>
        internal AsymmetricType Algorithm { get; set; }
        /// <summary>
        /// RSA parameters for actual RSA encryption
        /// </summary>
        internal RSAParameters InnerRSA { get; set; }
    }
}