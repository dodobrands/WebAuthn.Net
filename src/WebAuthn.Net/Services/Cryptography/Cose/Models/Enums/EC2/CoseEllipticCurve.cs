namespace WebAuthn.Net.Services.Cryptography.Cose.Models.Enums.EC2;

/// <summary>
///     <a href="https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves">COSE Elliptic Curves</a>
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://datatracker.ietf.org/doc/html/rfc9053#section-2.1">RFC9053 CBOR Object Signing and Encryption (COSE): Initial Algorithms - §2.1. ECDSA</a>
///     </para>
///     <para>
///         This document defines ECDSA as working only with the curves P-256, P-384, and P-521.
///         This document requires that the curves be encoded using the "EC2" (two coordinate elliptic curve) key type.
///     </para>
/// </remarks>
public enum CoseEllipticCurve
{
    /// <summary>
    ///     NIST P-256 also known as secp256r1
    /// </summary>
    P256 = 1,

    /// <summary>
    ///     NIST P-384 also known as secp384r1
    /// </summary>
    P384 = 2,

    /// <summary>
    ///     NIST P-521 also known as secp521r1
    /// </summary>
    P521 = 3
}
