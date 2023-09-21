namespace WebAuthn.Net.Models.Protocol.Enums;
#pragma warning disable CA1008
/// <summary>
///     Cryptographic Algorithm Identifier.
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://www.w3.org/TR/webauthn-3/#sctn-alg-identifier">Web Authentication: An API for accessing Public Key Credentials Level 3 - § 5.8.5. Cryptographic Algorithm Identifier</a>
///     </para>
///     <para>
///         <a href="https://www.iana.org/assignments/cose/cose.xhtml#algorithms">COSE Algorithms</a>
///     </para>
/// </remarks>
public enum CoseAlgorithmIdentifier
{
    /// <summary>
    ///     RSASSA-PKCS1-v1_5 w/ SHA-1
    /// </summary>
    Rs1 = -65535,

    /// <summary>
    ///     RSASSA-PKCS1-v1_5 w/ SHA-512
    /// </summary>
    Rs512 = -259,

    /// <summary>
    ///     RSASSA-PKCS1-v1_5 w/ SHA-384
    /// </summary>
    Rs384 = -258,

    /// <summary>
    ///     RSASSA-PKCS1-v1_5 w/ SHA-256
    /// </summary>
    Rs256 = -257,

    /// <summary>
    ///     RSASSA-PSS w/ SHA-512
    /// </summary>
    Ps512 = -39,

    /// <summary>
    ///     RSASSA-PSS w/ SHA-384
    /// </summary>
    Ps384 = -38,

    /// <summary>
    ///     RSASSA-PSS w/ SHA-256
    /// </summary>
    Ps256 = -37,

    /// <summary>
    ///     ECDSA w/ SHA-512
    /// </summary>
    Es512 = -36,

    /// <summary>
    ///     ECDSA w/ SHA-384
    /// </summary>
    Es384 = -35,

    /// <summary>
    ///     ECDSA w/ SHA-256
    /// </summary>
    Es256 = -7
}
#pragma warning restore CA1008
