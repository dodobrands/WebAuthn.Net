using System.Runtime.Serialization;

namespace WebAuthn.Net.Models.Protocol.Enums;

/// <summary>
///     Credential Type Enumeration
/// </summary>
/// <remarks>
///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#enum-credentialType">Web Authentication: An API for accessing Public Key Credentials Level 3 - §5.8.2. Credential Type Enumeration</a>
/// </remarks>
public enum PublicKeyCredentialType
{
    /// <summary>
    ///     Public key.
    /// </summary>
    [EnumMember(Value = "public-key")]
    PublicKey = 0
}
