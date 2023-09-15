using System.Runtime.Serialization;
using System.Text.Json.Serialization;
using WebAuthn.Net.Serialization.Json;

namespace WebAuthn.Net.Models.Protocol.Enums;

/// <summary>
///     Resident Key Requirement Enumeration.
/// </summary>
/// <remarks>
///     <a href="https://www.w3.org/TR/webauthn-3/#enum-residentKeyRequirement">Web Authentication: An API for accessing Public Key Credentials Level 3 - § 5.4.6. Resident Key Requirement Enumeration </a>
/// </remarks>
[JsonConverter(typeof(EnumMemberAttributeValueConverter<ResidentKeyRequirement>))]
public enum ResidentKeyRequirement
{
    /// <summary>
    ///     This value indicates the <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party</a> prefers creating
    ///     a <a href="https://www.w3.org/TR/webauthn-3/#server-side-credential">server-side credential</a>,
    ///     but will accept a <a href="https://www.w3.org/TR/webauthn-3/#client-side-discoverable-credential">client-side discoverable credential</a>.
    /// </summary>
    [EnumMember(Value = "discouraged")]
    Discouraged = 0,

    /// <summary>
    ///     This value indicates the <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party</a> strongly prefers creating
    ///     a <a href="https://www.w3.org/TR/webauthn-3/#client-side-discoverable-credential">client-side discoverable credential</a>,
    ///     but will accept a <a href="https://www.w3.org/TR/webauthn-3/#server-side-credential">server-side credential</a>.
    ///     For example, user agents should guide the user through setting up <a href="https://www.w3.org/TR/webauthn-3/#user-verification">user verification</a>
    ///     if needed to create a <a href="https://www.w3.org/TR/webauthn-3/#client-side-discoverable-credential">client-side discoverable credential</a> in this case.
    ///     This takes precedence over the setting of <a href="https://www.w3.org/TR/webauthn-3/#dom-authenticatorselectioncriteria-userverification">userVerification</a>.
    /// </summary>
    [EnumMember(Value = "preferred")]
    Preferred = 1,

    /// <summary>
    ///     This value indicates the <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party</a>
    ///     requires a <a href="https://www.w3.org/TR/webauthn-3/#client-side-discoverable-credential">client-side discoverable credential</a>,
    ///     and is prepared to receive an error
    ///     if a <a href="https://www.w3.org/TR/webauthn-3/#client-side-discoverable-credential">client-side discoverable credential</a> cannot be created.
    /// </summary>
    [EnumMember(Value = "required")]
    Required = 2
}
