using System.Runtime.Serialization;

namespace WebAuthn.Net.Models.Protocol.Enums;

/// <summary>
///     This enumeration defines the valid credential types.
/// </summary>
/// <remarks>
///     <a href="https://www.w3.org/TR/webauthn-2/#enumdef-publickeycredentialtype">Web Authentication: An API for accessing Public Key Credentials Level 2 - § 5.8.2. Credential Type Enumeration</a>
/// </remarks>
public enum PublicKeyCredentialType
{
    /// <summary>
    ///     Public key.
    /// </summary>
    [EnumMember(Value = "public-key")]
    PublicKey = 0
}
