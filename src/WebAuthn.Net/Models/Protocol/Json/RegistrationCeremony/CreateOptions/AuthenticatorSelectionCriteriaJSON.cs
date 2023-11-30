using System.Text.Json.Serialization;

namespace WebAuthn.Net.Models.Protocol.Json.RegistrationCeremony.CreateOptions;

/// <summary>
///     Authenticator Selection Criteria (dictionary AuthenticatorSelectionCriteria)
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dictionary-authenticatorSelection">Web Authentication: An API for accessing Public Key Credentials Level 3 - §5.4.4. Authenticator Selection Criteria (dictionary AuthenticatorSelectionCriteria</a>
///     </para>
///     <para>
///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-parseCreationOptionsFromJSON">
///             Web Authentication: An API for accessing Public Key Credentials Level 3 - §5.1.9. Deserialize Registration ceremony options - PublicKeyCredential's
///             parseCreationOptionsFromJSON() Method
///         </a>
///     </para>
///     <para>
///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dictdef-publickeycredentialcreationoptions">Web Authentication: An API for accessing Public Key Credentials Level 3 - §5.4. Options for Credential Creation (dictionary PublicKeyCredentialCreationOptions)</a>
///     </para>
/// </remarks>
// ReSharper disable once InconsistentNaming
public class AuthenticatorSelectionCriteriaJSON
{
    /// <summary>
    ///     Constructs <see cref="AuthenticatorSelectionCriteriaJSON" />.
    /// </summary>
    /// <param name="authenticatorAttachment">
    ///     If this member is present, eligible <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticators</a> are filtered to be only those authenticators attached with the specified
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#enum-attachment">authenticator attachment modality</a> (see also <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-authenticator-attachment-modality">§6.2.1 Authenticator Attachment Modality</a>). If
    ///     this member is absent, then any attachment modality is acceptable. The value SHOULD be a member of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#enumdef-authenticatorattachment">AuthenticatorAttachment</a> but
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client-platform">client platforms</a> MUST ignore unknown values, treating an unknown value as if the <a href="https://infra.spec.whatwg.org/#map-exists">member does not exist</a>.
    /// </param>
    /// <param name="residentKey">
    ///     Specifies the extent to which the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> desires to create a
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client-side-discoverable-credential">client-side discoverable credential</a>. For historical reasons the naming retains the deprecated "resident" terminology. The value SHOULD be a member of
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#enumdef-residentkeyrequirement">ResidentKeyRequirement</a> but <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client-platform">client platforms</a> MUST ignore unknown values, treating an unknown value
    ///     as if the <a href="https://infra.spec.whatwg.org/#map-exists">member does not exist</a>. If no value is given then the effective value is <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-residentkeyrequirement-required">required</a> if
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorselectioncriteria-requireresidentkey">requireResidentKey</a> is true or <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-residentkeyrequirement-discouraged">discouraged</a> if it is
    ///     false or absent.
    /// </param>
    /// <param name="requireResidentKey">
    ///     This member is retained for backwards compatibility with WebAuthn Level 1 and, for historical reasons, its naming retains the deprecated "resident" terminology for
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#discoverable-credential">discoverable credentials</a>. <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Parties</a> SHOULD set it to true if, and only if,
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorselectioncriteria-residentkey">residentKey</a> is set to <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-residentkeyrequirement-required">required</a>.
    /// </param>
    /// <param name="userVerification">
    ///     This member specifies the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party's</a> requirements regarding <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-verification">user verification</a> for
    ///     the <a href="https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-create">create()</a> operation. The value SHOULD be a member of
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#enumdef-userverificationrequirement">UserVerificationRequirement</a> but <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client-platform">client platforms</a> MUST ignore unknown values, treating an
    ///     unknown value as if the <a href="https://infra.spec.whatwg.org/#map-exists">member does not exist</a>.
    /// </param>
    public AuthenticatorSelectionCriteriaJSON(string? authenticatorAttachment, string? residentKey, bool? requireResidentKey, string? userVerification)
    {
        AuthenticatorAttachment = authenticatorAttachment;
        ResidentKey = residentKey;
        RequireResidentKey = requireResidentKey;
        UserVerification = userVerification;
    }

    /// <summary>
    ///     <para>
    ///         If this member is present, eligible <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticators</a> are filtered to be only those authenticators attached with the specified
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#enum-attachment">authenticator attachment modality</a> (see also <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-authenticator-attachment-modality">§6.2.1 Authenticator Attachment Modality</a>).
    ///         If this member is absent, then any attachment modality is acceptable. The value SHOULD be a member of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#enumdef-authenticatorattachment">AuthenticatorAttachment</a> but
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client-platform">client platforms</a> MUST ignore unknown values, treating an unknown value as if the <a href="https://infra.spec.whatwg.org/#map-exists">member does not exist</a>.
    ///     </para>
    ///     <para>
    ///         See also the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredential-authenticatorattachment">authenticatorAttachment</a> member of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#publickeycredential">PublicKeyCredential</a>,
    ///         which can tell what authenticator attachment modality was used in a successful <a href="https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-create">create()</a> operation.
    ///     </para>
    /// </summary>
    /// <remarks>DOMString</remarks>
    [JsonPropertyName("authenticatorAttachment")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string? AuthenticatorAttachment { get; }

    /// <summary>
    ///     <para>
    ///         Specifies the extent to which the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> desires to create a
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client-side-discoverable-credential">client-side discoverable credential</a>. For historical reasons the naming retains the deprecated "resident" terminology. The value SHOULD be a member of
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#enumdef-residentkeyrequirement">ResidentKeyRequirement</a> but <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client-platform">client platforms</a> MUST ignore unknown values, treating an unknown
    ///         value as if the <a href="https://infra.spec.whatwg.org/#map-exists">member does not exist</a>. If no value is given then the effective value is <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-residentkeyrequirement-required">required</a> if
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorselectioncriteria-requireresidentkey">requireResidentKey</a> is true or <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-residentkeyrequirement-discouraged">discouraged</a> if it
    ///         is false or absent.
    ///     </para>
    ///     <para>
    ///         See <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#enumdef-residentkeyrequirement">ResidentKeyRequirement</a> for the description of
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorselectioncriteria-residentkey">residentKey's</a> values and semantics.
    ///     </para>
    /// </summary>
    /// <remarks>DOMString</remarks>
    [JsonPropertyName("residentKey")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string? ResidentKey { get; }

    /// <summary>
    ///     This member is retained for backwards compatibility with WebAuthn Level 1 and, for historical reasons, its naming retains the deprecated "resident" terminology for
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#discoverable-credential">discoverable credentials</a>. <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Parties</a> SHOULD set it to true if, and only if,
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorselectioncriteria-residentkey">residentKey</a> is set to <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-residentkeyrequirement-required">required</a>.
    /// </summary>
    /// <remarks>boolean</remarks>
    [JsonPropertyName("requireResidentKey")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool? RequireResidentKey { get; }

    /// <summary>
    ///     <para>
    ///         This member specifies the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party's</a> requirements regarding <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-verification">user verification</a> for the
    ///         <a href="https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-create">create()</a> operation. The value SHOULD be a member of
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#enumdef-userverificationrequirement">UserVerificationRequirement</a> but <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client-platform">client platforms</a> MUST ignore unknown values, treating an
    ///         unknown value as if the <a href="https://infra.spec.whatwg.org/#map-exists">member does not exist</a>.
    ///     </para>
    ///     <para>
    ///         See <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#enumdef-userverificationrequirement">UserVerificationRequirement</a> for the description of
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorselectioncriteria-userverification">userVerification's</a> values and semantics.
    ///     </para>
    /// </summary>
    /// <remarks>DOMString</remarks>
    [JsonPropertyName("userVerification")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string? UserVerification { get; }
}
