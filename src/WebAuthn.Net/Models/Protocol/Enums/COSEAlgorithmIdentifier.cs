using System.Diagnostics.CodeAnalysis;
using System.Text.Json.Serialization;

namespace WebAuthn.Net.Models.Protocol.Enums;
#pragma warning disable CA1008
/// <summary>
///     Cryptographic Algorithm Identifier.
/// </summary>
/// <remarks>
///     <a href="https://www.w3.org/TR/webauthn-3/#sctn-alg-identifier">Web Authentication: An API for accessing Public Key Credentials Level 3 - § 5.8.5. Cryptographic Algorithm Identifier</a>
///     <br />
///     <a href="https://github.com/dotnet/runtime/blob/v7.0.11/src/libraries/System.Security.Cryptography.Cose/src/System/Security/Cryptography/Cose/KnownCoseAlgorithms.cs#L12-L22">.NET supported algorithms</a>
/// </remarks>
[SuppressMessage("ReSharper", "InconsistentNaming")]
public enum COSEAlgorithmIdentifier
{
    /// <summary>
    ///     RSASSA-PKCS1-v1_5 w/ SHA-512
    /// </summary>
    RS512 = -259,

    /// <summary>
    ///     RSASSA-PKCS1-v1_5 w/ SHA-384
    /// </summary>
    RS384 = -258,

    /// <summary>
    ///     RSASSA-PKCS1-v1_5 w/ SHA-256
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
    ///     ECDSA w/ SHA-256
    /// </summary>
    ES256 = -7
}
#pragma warning restore CA1008
