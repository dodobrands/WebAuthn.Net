using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace WebAuthn.Net.Models.Protocol.Json.AuthenticationCeremony.CreateOptions;

/// <summary>
///     Options for Assertion Generation (dictionary PublicKeyCredentialRequestOptions)
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dictionary-assertion-options">Web Authentication: An API for accessing Public Key Credentials Level 3 - §5.5. Options for Assertion Generation (dictionary PublicKeyCredentialRequestOptions)</a>
///     </para>
///     <para>
///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-parseRequestOptionsFromJSON">
///             Web Authentication: An API for accessing Public Key Credentials Level 3 - §5.1.10. Deserialize Authentication ceremony options - PublicKeyCredential's
///             parseRequestOptionsFromJSON() Methods
///         </a>
///     </para>
///     <para>
///         <a href="https://w3c.github.io/webappsec-credential-management/#credentialrequestoptions-dictionary">Credential Management Level 1 - §2.3.1. The CredentialRequestOptions Dictionary</a>
///     </para>
/// </remarks>
// ReSharper disable once InconsistentNaming
public class PublicKeyCredentialRequestOptionsJSON
{
    /// <summary>
    ///     Constructs <see cref="PublicKeyCredentialRequestOptionsJSON" />.
    /// </summary>
    /// <param name="challenge">
    ///     This member specifies a challenge that the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a> signs, along with other data, when producing an
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authentication-assertion">authentication assertion</a>. See the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-cryptographic-challenges">§13.4.3 Cryptographic Challenges</a> security consideration.
    /// </param>
    /// <param name="timeout">
    ///     This OPTIONAL member specifies a time, in milliseconds, that the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> is willing to wait for the call to complete. The value is treated as a hint, and MAY be overridden
    ///     by the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client">client</a>.
    /// </param>
    /// <param name="rpId">
    ///     This OPTIONAL member specifies the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#rp-id">RP ID</a> claimed by the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a>. The
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client">client</a> MUST verify that the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party's</a>
    ///     <a href="https://html.spec.whatwg.org/multipage/browsers.html#concept-origin">origin</a> matches the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#scope">scope</a> of this <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#rp-id">RP ID</a>. The
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a> MUST verify that this <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#rp-id">RP ID</a> exactly equals the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential-source-rpid">rpId</a> of the <a href="https://w3c.github.io/webappsec-credential-management/#concept-credential">credential</a> to be used for the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authentication-ceremony">authentication ceremony</a>.
    /// </param>
    /// <param name="allowCredentials">
    ///     <para>
    ///         This OPTIONAL member is used by the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client">client</a> to find <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticators</a> eligible for this
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authentication-ceremony">authentication ceremony</a>. It can be used in two ways:
    ///         <list type="bullet">
    ///             <item>
    ///                 <description>
    ///                     <para>
    ///                         If the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-account">user account</a> to authenticate is already identified (e.g., if the user has entered a username), then the
    ///                         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> SHOULD use this member to list
    ///                         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credential-descriptor-for-a-credential-record">credential descriptors for credential records</a> in the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-account">user account</a>.
    ///                         This SHOULD usually include all <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credential-record">credential records</a> in the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-account">user account</a>.
    ///                     </para>
    ///                     <para>
    ///                         The <a href="https://infra.spec.whatwg.org/#list-item">items</a> SHOULD specify <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialdescriptor-transports">transports</a> whenever possible. This helps the
    ///                         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client">client</a> optimize the user experience for any given situation. Also note that the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> does not
    ///                         need to filter the list when requesting <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-verification">user verification</a> — the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client">client</a> will automatically ignore
    ///                         non-eligible credentials if <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialrequestoptions-userverification">userVerification</a> is set to
    ///                         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-userverificationrequirement-required">required</a>.
    ///                     </para>
    ///                     <para>
    ///                         See also the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-credential-id-privacy-leak">§14.6.3 Privacy leak via credential IDs</a> privacy consideration.
    ///                     </para>
    ///                 </description>
    ///             </item>
    ///             <item>
    ///                 <description>
    ///                     <para>
    ///                         If the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-account">user account</a> to authenticate is not already identified, then the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> MAY leave
    ///                         this member <a href="https://infra.spec.whatwg.org/#list-empty">empty</a> or unspecified. In this case, only <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#discoverable-credential">discoverable credentials</a> will be utilized in this
    ///                         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authentication-ceremony">authentication ceremony</a>, and the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-account">user account</a> MAY be identified by the
    ///                         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorassertionresponse-userhandle">userHandle</a> of the resulting
    ///                         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticatorassertionresponse">AuthenticatorAssertionResponse</a>. If the available <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticators</a>
    ///                         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#contains">contain</a> more than one <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#discoverable-credential">discoverable credential</a>
    ///                         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#scope">scoped</a> to the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a>, the credentials are displayed by the
    ///                         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client-platform">client platform</a> or <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a> for the user to select from (see
    ///                         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticatorGetAssertion-prompt-select-credential">step 7</a> of
    ///                         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-op-get-assertion">§6.3.3 The authenticatorGetAssertion Operation</a>).
    ///                     </para>
    ///                 </description>
    ///             </item>
    ///         </list>
    ///     </para>
    ///     <para>If not <a href="https://infra.spec.whatwg.org/#list-empty">empty</a>, the client MUST return an error if none of the listed credentials can be used.</para>
    ///     <para>The list is ordered in descending order of preference: the first item in the list is the most preferred credential, and the last is the least preferred.</para>
    /// </param>
    /// <param name="userVerification">
    ///     This OPTIONAL member specifies the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party's</a> requirements regarding
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-verification">user verification</a> for the <a href="https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-get">get()</a> operation. The value SHOULD be a member of
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#enumdef-userverificationrequirement">UserVerificationRequirement</a> but <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client-platform">client platforms</a> MUST ignore unknown values, treating an
    ///     unknown value as if the <a href="https://infra.spec.whatwg.org/#map-exists">member does not exist</a>. Eligible authenticators are filtered to only those capable of satisfying this requirement.
    /// </param>
    /// <param name="hints">This OPTIONAL member contains zero or more elements from <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#enumdef-publickeycredentialhints">PublicKeyCredentialHints</a> to guide the user agent in interacting with the user.</param>
    /// <param name="attestation">
    ///     The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> MAY use this OPTIONAL member to specify a preference regarding
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-conveyance">attestation conveyance</a>. Its value SHOULD be a member of
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#enumdef-attestationconveyancepreference">AttestationConveyancePreference</a>. <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client-platform">Client platforms</a> MUST ignore unknown values, treating an
    ///     unknown value as if the <a href="https://infra.spec.whatwg.org/#map-exists">member does not exist</a>.
    /// </param>
    /// <param name="attestationFormats">
    ///     The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> MAY use this OPTIONAL member to specify a preference regarding the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation">attestation</a> statement format used
    ///     by the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a>. Values SHOULD be taken from the <a href="https://www.iana.org/assignments/webauthn/webauthn.xhtml">IANA "WebAuthn Attestation Statement Format Identifiers" registry</a>
    ///     established by <a href="https://www.rfc-editor.org/rfc/rfc8809.html">RFC 8809</a>. Values are ordered from most preferable to least preferable. This parameter is advisory and the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a> MAY
    ///     use an attestation statement not enumerated in this parameter.
    /// </param>
    /// <param name="extensions">
    ///     The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> MAY use this OPTIONAL member to provide <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client-extension-input">client extension inputs</a>
    ///     requesting additional processing by the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client">client</a> and <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a>.
    /// </param>
    [JsonConstructor]
    public PublicKeyCredentialRequestOptionsJSON(
        string challenge,
        uint? timeout,
        string? rpId,
        PublicKeyCredentialDescriptorJSON[]? allowCredentials,
        string? userVerification,
        string[]? hints,
        string? attestation,
        string[]? attestationFormats,
        Dictionary<string, JsonElement>? extensions)
    {
        Challenge = challenge;
        Timeout = timeout;
        RpId = rpId;
        AllowCredentials = allowCredentials;
        UserVerification = userVerification;
        Hints = hints;
        Attestation = attestation;
        AttestationFormats = attestationFormats;
        Extensions = extensions;
    }

    /// <summary>
    ///     This member specifies a challenge that the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a> signs, along with other data, when producing an
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authentication-assertion">authentication assertion</a>. See the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-cryptographic-challenges">§13.4.3 Cryptographic Challenges</a> security consideration.
    /// </summary>
    /// <remarks>
    ///     Base64URLString
    /// </remarks>
    [Required]
    [JsonPropertyName("challenge")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string Challenge { get; }

    /// <summary>
    ///     This OPTIONAL member specifies a time, in milliseconds, that the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> is willing to wait for the call to complete. The value is treated as a hint, and MAY be overridden by the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client">client</a>.
    /// </summary>
    [JsonPropertyName("timeout")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public uint? Timeout { get; }

    /// <summary>
    ///     <para>
    ///         This OPTIONAL member specifies the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#rp-id">RP ID</a> claimed by the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a>. The
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client">client</a> MUST verify that the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party's</a>
    ///         <a href="https://html.spec.whatwg.org/multipage/browsers.html#concept-origin">origin</a> matches the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#scope">scope</a> of this <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#rp-id">RP ID</a>. The
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a> MUST verify that this <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#rp-id">RP ID</a> exactly equals the
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential-source-rpid">rpId</a> of the <a href="https://w3c.github.io/webappsec-credential-management/#concept-credential">credential</a> to be used for the
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authentication-ceremony">authentication ceremony</a>.
    ///     </para>
    ///     <para>
    ///         If not specified, its value will be the <a href="https://w3c.github.io/webappsec-credential-management/#credentialscontainer">CredentialsContainer</a> object's
    ///         <a href="https://html.spec.whatwg.org/multipage/webappapis.html#relevant-settings-object">relevant settings object's</a> <a href="https://html.spec.whatwg.org/multipage/webappapis.html#concept-settings-object-origin">origin's</a>
    ///         <a href="https://html.spec.whatwg.org/multipage/browsers.html#concept-origin-effective-domain">effective domain</a>.
    ///     </para>
    /// </summary>
    /// <remarks>
    ///     <a href="https://webidl.spec.whatwg.org/#idl-USVString">USVString</a>
    /// </remarks>
    [JsonPropertyName("rpId")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string? RpId { get; }

    /// <summary>
    ///     <para>
    ///         This OPTIONAL member is used by the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client">client</a> to find <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticators</a> eligible for this
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authentication-ceremony">authentication ceremony</a>. It can be used in two ways:
    ///         <list type="bullet">
    ///             <item>
    ///                 <description>
    ///                     <para>
    ///                         If the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-account">user account</a> to authenticate is already identified (e.g., if the user has entered a username), then the
    ///                         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> SHOULD use this member to list
    ///                         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credential-descriptor-for-a-credential-record">credential descriptors for credential records</a> in the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-account">user account</a>.
    ///                         This SHOULD usually include all <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credential-record">credential records</a> in the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-account">user account</a>.
    ///                     </para>
    ///                     <para>
    ///                         The <a href="https://infra.spec.whatwg.org/#list-item">items</a> SHOULD specify <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialdescriptor-transports">transports</a> whenever possible. This helps the
    ///                         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client">client</a> optimize the user experience for any given situation. Also note that the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> does not
    ///                         need to filter the list when requesting <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-verification">user verification</a> — the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client">client</a> will automatically ignore
    ///                         non-eligible credentials if <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialrequestoptions-userverification">userVerification</a> is set to
    ///                         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-userverificationrequirement-required">required</a>.
    ///                     </para>
    ///                     <para>
    ///                         See also the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-credential-id-privacy-leak">§14.6.3 Privacy leak via credential IDs</a> privacy consideration.
    ///                     </para>
    ///                 </description>
    ///             </item>
    ///             <item>
    ///                 <description>
    ///                     <para>
    ///                         If the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-account">user account</a> to authenticate is not already identified, then the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> MAY leave
    ///                         this member <a href="https://infra.spec.whatwg.org/#list-empty">empty</a> or unspecified. In this case, only <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#discoverable-credential">discoverable credentials</a> will be utilized in this
    ///                         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authentication-ceremony">authentication ceremony</a>, and the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-account">user account</a> MAY be identified by the
    ///                         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorassertionresponse-userhandle">userHandle</a> of the resulting
    ///                         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticatorassertionresponse">AuthenticatorAssertionResponse</a>. If the available <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticators</a>
    ///                         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#contains">contain</a> more than one <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#discoverable-credential">discoverable credential</a>
    ///                         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#scope">scoped</a> to the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a>, the credentials are displayed by the
    ///                         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client-platform">client platform</a> or <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a> for the user to select from (see
    ///                         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticatorGetAssertion-prompt-select-credential">step 7</a> of
    ///                         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-op-get-assertion">§6.3.3 The authenticatorGetAssertion Operation</a>).
    ///                     </para>
    ///                 </description>
    ///             </item>
    ///         </list>
    ///     </para>
    ///     <para>If not <a href="https://infra.spec.whatwg.org/#list-empty">empty</a>, the client MUST return an error if none of the listed credentials can be used.</para>
    ///     <para>The list is ordered in descending order of preference: the first item in the list is the most preferred credential, and the last is the least preferred.</para>
    /// </summary>
    /// <remarks>
    ///     defaulting to []
    /// </remarks>
    [JsonPropertyName("allowCredentials")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public PublicKeyCredentialDescriptorJSON[]? AllowCredentials { get; }

    /// <summary>
    ///     <para>
    ///         This OPTIONAL member specifies the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party's</a> requirements regarding <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-verification">user verification</a> for the
    ///         <a href="https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-get">get()</a> operation. The value SHOULD be a member of
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#enumdef-userverificationrequirement">UserVerificationRequirement</a> but <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client-platform">client platforms</a> MUST ignore unknown values, treating an
    ///         unknown value as if the <a href="https://infra.spec.whatwg.org/#map-exists">member does not exist</a>. Eligible authenticators are filtered to only those capable of satisfying this requirement.
    ///     </para>
    ///     <para>
    ///         See <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#enumdef-userverificationrequirement">UserVerificationRequirement</a> for the description of
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorselectioncriteria-userverification">userVerification's</a> values and semantics.
    ///     </para>
    /// </summary>
    [JsonPropertyName("userVerification")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string? UserVerification { get; }

    /// <summary>
    ///     This OPTIONAL member contains zero or more elements from <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#enumdef-publickeycredentialhints">PublicKeyCredentialHints</a> to guide the user agent in interacting with the user.
    /// </summary>
    /// <remarks>
    ///     defaulting to []
    /// </remarks>
    [JsonPropertyName("hints")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string[]? Hints { get; }

    /// <summary>
    ///     The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> MAY use this OPTIONAL member to specify a preference regarding <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-conveyance">attestation conveyance</a>. Its
    ///     value SHOULD be a member of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#enumdef-attestationconveyancepreference">AttestationConveyancePreference</a>. <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client-platform">Client platforms</a> MUST ignore
    ///     unknown values, treating an unknown value as if the <a href="https://infra.spec.whatwg.org/#map-exists">member does not exist</a>.
    /// </summary>
    /// <remarks>
    ///     defaulting to <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-attestationconveyancepreference-none">"none"</a>
    /// </remarks>
    [JsonPropertyName("attestation")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string? Attestation { get; }

    /// <summary>
    ///     The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> MAY use this OPTIONAL member to specify a preference regarding the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation">attestation</a> statement format used
    ///     by the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a>. Values SHOULD be taken from the <a href="https://www.iana.org/assignments/webauthn/webauthn.xhtml">IANA "WebAuthn Attestation Statement Format Identifiers" registry</a>
    ///     established by <a href="https://www.rfc-editor.org/rfc/rfc8809.html">RFC 8809</a>. Values are ordered from most preferable to least preferable. This parameter is advisory and the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a> MAY
    ///     use an attestation statement not enumerated in this parameter.
    /// </summary>
    /// <remarks>
    ///     defaulting to []
    /// </remarks>
    [JsonPropertyName("attestationFormats")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string[]? AttestationFormats { get; }

    /// <summary>
    ///     <para>
    ///         The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> MAY use this OPTIONAL member to provide <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client-extension-input">client extension inputs</a> requesting additional
    ///         processing by the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client">client</a> and <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a>.
    ///     </para>
    ///     <para>
    ///         The extensions framework is defined in <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-extensions">§9 WebAuthn Extensions</a>. Some extensions are defined in
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-defined-extensions">§10 Defined Extensions</a>; consult the <a href="https://www.iana.org/assignments/webauthn/webauthn.xhtml">IANA "WebAuthn Extension Identifiers" registry</a> established by
    ///         <a href="https://www.rfc-editor.org/rfc/rfc8809.html">RFC 8809</a> for an up-to-date list of registered <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#webauthn-extensions">WebAuthn Extensions</a>.
    ///     </para>
    /// </summary>
    [JsonPropertyName("extensions")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public Dictionary<string, JsonElement>? Extensions { get; }
}
