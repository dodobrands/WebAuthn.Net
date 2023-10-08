using System.Runtime.Serialization;

namespace WebAuthn.Net.Models.Protocol.Enums;

/// <summary>
///     User Verification Requirement Enumeration
/// </summary>
/// <remarks>
///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#enum-userVerificationRequirement">Web Authentication: An API for accessing Public Key Credentials Level 3 - §5.8.6. User Verification Requirement Enumeration</a>
/// </remarks>
public enum UserVerificationRequirement
{
    /// <summary>
    ///     The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> requires <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-verification">user verification</a> for the operation and will fail the overall
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#ceremony">ceremony</a> if the response does not have the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-flags-uv">UV</a>
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-flags">flag</a> set. The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client">client</a> MUST return an error if
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-verification">user verification</a> cannot be performed.
    /// </summary>
    [EnumMember(Value = "required")]
    Required = 0,

    /// <summary>
    ///     The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> prefers <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-verification">user verification</a> for the operation if possible, but will not fail the operation if the
    ///     response does not have the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-flags-uv">UV</a> <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-flags">flag</a> set.
    /// </summary>
    [EnumMember(Value = "preferred")]
    Preferred = 1,

    /// <summary>
    ///     The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> does not want <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-verification">user verification</a> employed during the operation (e.g., in the interest of
    ///     minimizing disruption to the user interaction flow).
    /// </summary>
    [EnumMember(Value = "discouraged")]
    Discouraged = 2
}
