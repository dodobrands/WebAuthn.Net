using System.Runtime.Serialization;
using System.Text.Json.Serialization;
using WebAuthn.Net.Serialization.Json;

namespace WebAuthn.Net.Models.Protocol.Enums;

/// <summary>
///     This enumeration defines the requirements of <a href="https://www.w3.org/TR/webauthn-3/#user-verification">user verification</a> for a <a href="https://www.w3.org/TR/webauthn-3/#webauthn-relying-party">WebAuthn Relying Party</a>.
/// </summary>
/// <remarks>
///     <a href="https://www.w3.org/TR/webauthn-3/#enum-userVerificationRequirement">Web Authentication: An API for accessing Public Key Credentials Level 3 - § 5.8.6. User Verification Requirement Enumeration</a>
/// </remarks>
[JsonConverter(typeof(EnumAsStringConverter<UserVerificationRequirement>))]
public enum UserVerificationRequirement
{
    /// <summary>
    ///     Indicates that the <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party</a>
    ///     requires <a href="https://www.w3.org/TR/webauthn-3/#user-verification">user verification</a> for the operation and will fail the operation
    ///     if the response does not have the <a href="https://www.w3.org/TR/webauthn-3/#uv">UV</a> <a href="https://www.w3.org/TR/webauthn-3/#flags">flag</a> set.
    /// </summary>
    [EnumMember(Value = "required")]
    Required = 0,

    /// <summary>
    ///     Indicates that the <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party</a>
    ///     prefers <a href="https://www.w3.org/TR/webauthn-3/#user-verification">user verification</a> for the operation if possible, but will not fail the operation
    ///     if the response does not have the <a href="https://www.w3.org/TR/webauthn-3/#uv">UV</a> <a href="https://www.w3.org/TR/webauthn-3/#flags">flag</a> set.
    /// </summary>
    [EnumMember(Value = "preferred")]
    Preferred = 1,

    /// <summary>
    ///     This value indicates that the <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party</a>
    ///     does not want <a href="https://www.w3.org/TR/webauthn-3/#user-verification">user verification</a> employed during the operation
    ///     (e.g., in the interest of minimizing disruption to the user interaction flow).
    /// </summary>
    [EnumMember(Value = "discouraged")]
    Discouraged = 2
}
