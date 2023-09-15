using System.Runtime.Serialization;
using System.Text.Json.Serialization;
using WebAuthn.Net.Serialization.Json;

namespace WebAuthn.Net.Models.Protocol.Enums;

/// <summary>
///     Authenticator Attachment Enumeration
/// </summary>
/// <remarks>
///     <a href="https://www.w3.org/TR/webauthn-3/#enum-attachment">Web Authentication: An API for accessing Public Key Credentials Level 3 - § 5.4.5. Authenticator Attachment Enumeration</a>
/// </remarks>
[JsonConverter(typeof(EnumMemberAttributeValueConverter<AuthenticatorAttachment>))]
public enum AuthenticatorAttachment
{
    /// <summary>
    ///     This value indicates <a href="https://www.w3.org/TR/webauthn-3/#platform-attachment">platform attachment</a>.
    /// </summary>
    [EnumMember(Value = "platform")]
    Platform = 0,

    /// <summary>
    ///     This value indicates <a href="https://www.w3.org/TR/webauthn-3/#cross-platform-attachment">cross-platform attachment</a>.
    /// </summary>
    [EnumMember(Value = "cross-platform")]
    CrossPlatform = 1
}
