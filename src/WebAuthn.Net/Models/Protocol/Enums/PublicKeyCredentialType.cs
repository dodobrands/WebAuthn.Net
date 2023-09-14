using System.Runtime.Serialization;
using System.Text.Json.Serialization;
using WebAuthn.Net.Serialization.Json;

namespace WebAuthn.Net.Models.Protocol.Enums;

/// <summary>
///     This enumeration defines the valid credential types.
/// </summary>
/// <remarks>
///     <a href="https://www.w3.org/TR/webauthn-3/#enumdef-publickeycredentialtype">Web Authentication: An API for accessing Public Key Credentials Level 3 - § 5.8.2. Credential Type Enumeration</a>
/// </remarks>
[JsonConverter(typeof(EnumValueAttributeConverter<PublicKeyCredentialType>))]
public enum PublicKeyCredentialType
{
    /// <summary>
    ///     Public key.
    /// </summary>
    [EnumMember(Value = "public-key")]
    PublicKey = 0
}
