using System.Diagnostics.CodeAnalysis;

namespace WebAuthn.Net.Services.Serialization.Cose.Models.Enums;

/// <summary>
///     Cryptographic Algorithm Identifier.
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-alg-identifier">Web Authentication: An API for accessing Public Key Credentials Level 3 - §5.8.5. Cryptographic Algorithm Identifier</a>
///     </para>
///     <para>
///         <a href="https://www.iana.org/assignments/cose/cose.xhtml#algorithms">COSE Algorithms</a>
///     </para>
/// </remarks>
[SuppressMessage("ReSharper", "InconsistentNaming")]
public enum CoseAlgorithm
{
    /// <summary>
    ///     RSASSA-PKCS1-v1_5 using SHA-1
    /// </summary>
    RS1 = -65535,

    /// <summary>
    ///     RSASSA-PKCS1-v1_5 using SHA-512
    /// </summary>
    RS512 = -259,

    /// <summary>
    ///     RSASSA-PKCS1-v1_5 using SHA-384
    /// </summary>
    RS384 = -258,

    /// <summary>
    ///     RSASSA-PKCS1-v1_5 using SHA-256
    /// </summary>
    RS256 = -257,

    /// <summary>
    ///     RSASSA-PSS w/ SHA-512
    /// </summary>
    PS512 = -39,

    /// <summary>
    ///     RSASSA-PSS w/ SHA-384
    /// </summary>
    PS384 = -38,

    /// <summary>
    ///     RSASSA-PSS w/ SHA-256
    /// </summary>
    PS256 = -37,

    /// <summary>
    ///     ECDSA w/ SHA-512
    /// </summary>
    ES512 = -36,

    /// <summary>
    ///     ECDSA w/ SHA-384
    /// </summary>
    ES384 = -35,

    /// <summary>
    ///     EdDSA
    /// </summary>
    EdDSA = -8,

    /// <summary>
    ///     ECDSA w/ SHA-256
    /// </summary>
    ES256 = -7
}
