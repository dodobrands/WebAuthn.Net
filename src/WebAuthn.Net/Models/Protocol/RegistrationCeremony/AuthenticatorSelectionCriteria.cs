using System.Text.Json.Serialization;
using WebAuthn.Net.Models.Protocol.Enums;

namespace WebAuthn.Net.Models.Protocol.RegistrationCeremony;

/// <summary>
///     Authenticator Selection Criteria
/// </summary>
/// <remarks>
///     <a href="https://www.w3.org/TR/webauthn-3/#dictionary-authenticatorSelection">Web Authentication: An API for accessing Public Key Credentials Level 3 - § 5.4.4. Authenticator Selection Criteria</a>
/// </remarks>
public class AuthenticatorSelectionCriteria
{
    /// <summary>
    ///     Constructs <see cref="AuthenticatorSelectionCriteria" />.
    /// </summary>
    /// <param name="authenticatorAttachment">
    ///     If this member is present, eligible authenticators are filtered to only authenticators attached with the specified <see cref="AuthenticatorAttachment" />.
    ///     The value should be a member of <see cref="AuthenticatorAttachment" /> but <a href="https://www.w3.org/TR/webauthn-3/#client-platform">client platforms</a>
    ///     must ignore unknown values, treating an unknown value as if the <a href="https://infra.spec.whatwg.org/#map-exists">member does not exist</a>.
    /// </param>
    /// <param name="residentKey">
    ///     Specifies the extent to which the <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party</a> desires to
    ///     create a <a href="https://www.w3.org/TR/webauthn-3/#client-side-discoverable-credential">client-side discoverable credential</a>.
    ///     For historical reasons the naming retains the deprecated "resident" terminology.
    ///     The value should be a member of <see cref="ResidentKeyRequirement" />
    ///     but <a href="https://www.w3.org/TR/webauthn-3/#client-platform">client platforms</a> must ignore unknown values,
    ///     treating an unknown value as if the <a href="https://infra.spec.whatwg.org/#map-exists">member does not exist</a>.
    ///     If no value is given then the effective value is <see cref="ResidentKeyRequirement.Required" />
    ///     if <see cref="RequireResidentKey" /> is <see langword="true" /> or <see cref="ResidentKeyRequirement.Discouraged" /> if it is <see langword="false" /> or absent.
    /// </param>
    /// <param name="requireResidentKey">
    ///     This member is retained for backwards compatibility with WebAuthn Level 1 and, for historical reasons,
    ///     its naming retains the deprecated "resident" terminology for <a href="https://www.w3.org/TR/webauthn-3/#discoverable-credential">discoverable credentials</a>.
    ///     <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Parties</a> should set it to <see langword="true" />
    ///     if, and only if, <see cref="ResidentKey" /> is set to <see cref="ResidentKeyRequirement.Required" />.
    /// </param>
    /// <param name="userVerification">
    ///     This member describes the <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party's</a> requirements regarding user verification
    ///     for the <a href="https://www.w3.org/TR/credential-management-1/#dom-credentialscontainer-create">create()</a> operation.
    ///     Eligible authenticators are filtered to only those capable of satisfying this requirement.
    ///     The value should be a member of <see cref="UserVerificationRequirement" />
    ///     but <a href="https://www.w3.org/TR/webauthn-3/#client-platform">client platforms</a> must ignore unknown values,
    ///     treating an unknown value as if the <a href="https://infra.spec.whatwg.org/#map-exists">member does not exist</a>.
    /// </param>
    [JsonConstructor]
    public AuthenticatorSelectionCriteria(
        AuthenticatorAttachment? authenticatorAttachment,
        ResidentKeyRequirement? residentKey,
        bool? requireResidentKey,
        UserVerificationRequirement? userVerification)
    {
        AuthenticatorAttachment = authenticatorAttachment;
        ResidentKey = residentKey;
        RequireResidentKey = requireResidentKey;
        UserVerification = userVerification;
    }

    /// <summary>
    ///     If this member is present, eligible authenticators are filtered to only authenticators attached with the specified <see cref="AuthenticatorAttachment" />.
    ///     The value should be a member of <see cref="AuthenticatorAttachment" /> but <a href="https://www.w3.org/TR/webauthn-3/#client-platform">client platforms</a>
    ///     must ignore unknown values, treating an unknown value as if the <a href="https://infra.spec.whatwg.org/#map-exists">member does not exist</a>.
    /// </summary>
    [JsonPropertyName("authenticatorAttachment")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public AuthenticatorAttachment? AuthenticatorAttachment { get; }

    /// <summary>
    ///     Specifies the extent to which the <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party</a> desires to
    ///     create a <a href="https://www.w3.org/TR/webauthn-3/#client-side-discoverable-credential">client-side discoverable credential</a>.
    ///     For historical reasons the naming retains the deprecated "resident" terminology.
    ///     The value should be a member of <see cref="ResidentKeyRequirement" />
    ///     but <a href="https://www.w3.org/TR/webauthn-3/#client-platform">client platforms</a> must ignore unknown values,
    ///     treating an unknown value as if the <a href="https://infra.spec.whatwg.org/#map-exists">member does not exist</a>.
    ///     If no value is given then the effective value is <see cref="ResidentKeyRequirement.Required" />
    ///     if <see cref="RequireResidentKey" /> is <see langword="true" /> or <see cref="ResidentKeyRequirement.Discouraged" /> if it is <see langword="false" /> or absent.
    /// </summary>
    [JsonPropertyName("residentKey")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public ResidentKeyRequirement? ResidentKey { get; }

    /// <summary>
    ///     This member is retained for backwards compatibility with WebAuthn Level 1 and, for historical reasons,
    ///     its naming retains the deprecated "resident" terminology for <a href="https://www.w3.org/TR/webauthn-3/#discoverable-credential">discoverable credentials</a>.
    ///     <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Parties</a> should set it to <see langword="true" />
    ///     if, and only if, <see cref="ResidentKey" /> is set to <see cref="ResidentKeyRequirement.Required" />.
    /// </summary>
    [JsonPropertyName("requireResidentKey")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? RequireResidentKey { get; }

    /// <summary>
    ///     This member describes the <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party's</a> requirements regarding user verification
    ///     for the <a href="https://www.w3.org/TR/credential-management-1/#dom-credentialscontainer-create">create()</a> operation.
    ///     Eligible authenticators are filtered to only those capable of satisfying this requirement.
    ///     The value should be a member of <see cref="UserVerificationRequirement" />
    ///     but <a href="https://www.w3.org/TR/webauthn-3/#client-platform">client platforms</a> must ignore unknown values,
    ///     treating an unknown value as if the <a href="https://infra.spec.whatwg.org/#map-exists">member does not exist</a>.
    /// </summary>
    [JsonPropertyName("userVerification")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public UserVerificationRequirement? UserVerification { get; }
}
