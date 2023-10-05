using System;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Serialization.Json;
using WebAuthn.Net.Services.Static;

namespace WebAuthn.Net.Models.Protocol.AuthenticationCeremony;

/// <summary>
///     An object that contains the attributes that are returned to the caller when a new assertion is requested.
/// </summary>
/// <remarks>
///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#iface-pkcredential">Web Authentication: An API for accessing Public Key Credentials Level 3 - §5.1. PublicKeyCredential</a>
/// </remarks>
public class PublicKeyCredential
{
    /// <summary>
    ///     Constructs <see cref="PublicKeyCredential" />.
    /// </summary>
    /// <param name="id">
    ///     <list type="bullet">
    ///         <item>
    ///             <term>
    ///                 <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#ref-for-dom-credential-id">WebAuthn</a>
    ///             </term>
    ///             <description>
    ///                 This attribute is inherited from <a href="https://w3c.github.io/webappsec-credential-management/#credential">Credential</a>, though <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#publickeycredential">PublicKeyCredential</a> overrides
    ///                 <a href="https://w3c.github.io/webappsec-credential-management/#credential">Credential's</a> getter, instead returning the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#base64url-encoding">base64url encoding</a> of the data contained in the object’s
    ///                 <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredential-identifier-slot">[[identifier]]</a> <a href="https://tc39.es/ecma262/#sec-object-internal-methods-and-internal-slots">internal slot</a>.
    ///             </description>
    ///         </item>
    ///         <item>
    ///             <term>
    ///                 <a href="https://w3c.github.io/webappsec-credential-management/#dom-credential-id">Credential Management</a>
    ///             </term>
    ///             <description>
    ///                 The credential’s identifier. The requirements for the identifier are distinct for each type of <a href="https://w3c.github.io/webappsec-credential-management/#concept-credential">credential</a>. It might represent a username for username/password tuples, for
    ///                 example.
    ///             </description>
    ///         </item>
    ///     </list>
    /// </param>
    /// <param name="type">
    ///     This attribute’s getter returns the value of the object’s <a href="https://webidl.spec.whatwg.org/#dfn-interface-object">interface object's</a> <a href="https://w3c.github.io/webappsec-credential-management/#dom-credential-type-slot">[[type]]</a> slot, which
    ///     specifies the <a href="https://w3c.github.io/webappsec-credential-management/#credential-credential-type">credential type</a> represented by this object.
    /// </param>
    /// <param name="rawId">This attribute returns the <a href="https://webidl.spec.whatwg.org/#idl-ArrayBuffer">ArrayBuffer</a> contained in the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredential-identifier-slot">[[identifier]]</a> internal slot.</param>
    /// <param name="response">
    ///     This attribute contains the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator's</a> response to the client’s request to either create a
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential">public key</a> credential, or generate an <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authentication-assertion">authentication assertion</a>.
    /// </param>
    /// <param name="authenticatorAttachment">
    ///     This attribute reports the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator-attachment-modality">authenticator attachment modality</a> in effect at the time the
    ///     <a href="https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-get">navigator.credentials.get()</a> method successfully complete. The attribute’s value SHOULD be a member of
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#enumdef-authenticatorattachment">AuthenticatorAttachment</a>. <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Parties</a> SHOULD treat unknown values as if the value were null.
    /// </param>
    /// <exception cref="ArgumentNullException"><paramref name="id" /> is <see langword="null" /></exception>
    /// <exception cref="ArgumentException"><paramref name="id" /> contains surrogate pairs (it is not a valid instance of <a href="https://webidl.spec.whatwg.org/#idl-USVString">USVString</a>)</exception>
    /// <exception cref="InvalidEnumArgumentException"><paramref name="type" /> contains a value that is not defined in <see cref="PublicKeyCredentialType" /></exception>
    [JsonConstructor]
    public PublicKeyCredential(
        string id,
        PublicKeyCredentialType type,
        byte[] rawId,
        AuthenticatorAssertionResponse response,
        AuthenticatorAttachment? authenticatorAttachment)
    {
        ArgumentNullException.ThrowIfNull(id, nameof(id));
        if (!UsvStringValidator.IsValid(id))
        {
            throw new ArgumentException($"{nameof(id)} must be a string that doesn't contain surrogate pairs.", nameof(id));
        }

        if (!Enum.IsDefined(type))
        {
            throw new InvalidEnumArgumentException(nameof(type), (int) type, typeof(PublicKeyCredentialType));
        }

        ArgumentNullException.ThrowIfNull(rawId, nameof(rawId));
        ArgumentNullException.ThrowIfNull(response, nameof(response));

        Id = id;
        Type = type;
        RawId = rawId;
        Response = response;
        if (authenticatorAttachment.HasValue)
        {
            AuthenticatorAttachment = Enum.IsDefined(authenticatorAttachment.Value)
                ? authenticatorAttachment.Value
                : null;
        }
    }

    /// <summary>
    ///     <list type="bullet">
    ///         <item>
    ///             <term>
    ///                 <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#ref-for-dom-credential-id">WebAuthn</a>
    ///             </term>
    ///             <description>
    ///                 This attribute is inherited from <a href="https://w3c.github.io/webappsec-credential-management/#credential">Credential</a>, though <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#publickeycredential">PublicKeyCredential</a> overrides
    ///                 <a href="https://w3c.github.io/webappsec-credential-management/#credential">Credential's</a> getter, instead returning the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#base64url-encoding">base64url encoding</a> of the data contained in the object’s
    ///                 <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredential-identifier-slot">[[identifier]]</a> <a href="https://tc39.es/ecma262/#sec-object-internal-methods-and-internal-slots">internal slot</a>.
    ///             </description>
    ///         </item>
    ///         <item>
    ///             <term>
    ///                 <a href="https://w3c.github.io/webappsec-credential-management/#dom-credential-id">Credential Management</a>
    ///             </term>
    ///             <description>
    ///                 The credential’s identifier. The requirements for the identifier are distinct for each type of <a href="https://w3c.github.io/webappsec-credential-management/#concept-credential">credential</a>. It might represent a username for username/password tuples,
    ///                 for example.
    ///             </description>
    ///         </item>
    ///     </list>
    /// </summary>
    [JsonPropertyName("id")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string Id { get; }

    /// <summary>
    ///     This attribute’s getter returns the value of the object’s <a href="https://webidl.spec.whatwg.org/#dfn-interface-object">interface object's</a> <a href="https://w3c.github.io/webappsec-credential-management/#dom-credential-type-slot">[[type]]</a> slot, which specifies the
    ///     <a href="https://w3c.github.io/webappsec-credential-management/#credential-credential-type">credential type</a> represented by this object.
    /// </summary>
    [JsonPropertyName("type")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public PublicKeyCredentialType Type { get; }

    /// <summary>
    ///     This attribute returns the <a href="https://webidl.spec.whatwg.org/#idl-ArrayBuffer">ArrayBuffer</a> contained in the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredential-identifier-slot">[[identifier]]</a> internal slot.
    /// </summary>
    [JsonPropertyName("rawId")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    [JsonConverter(typeof(Base64UrlConverter))]
    public byte[] RawId { get; }

    /// <summary>
    ///     This attribute contains the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator's</a> response to the client’s request to either create a <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential">public key</a>
    ///     credential, or generate an <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authentication-assertion">authentication assertion</a>.
    /// </summary>
    [JsonPropertyName("response")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public AuthenticatorAssertionResponse Response { get; }

    /// <summary>
    ///     This attribute reports the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator-attachment-modality">authenticator attachment modality</a> in effect at the time the
    ///     <a href="https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-get">navigator.credentials.get()</a> method successfully complete. The attribute’s value SHOULD be a member of
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#enumdef-authenticatorattachment">AuthenticatorAttachment</a>. <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Parties</a> SHOULD treat unknown values as if the value were null.
    /// </summary>
    /// <remarks>
    ///     <para>
    ///         If, as the result of an <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authentication-ceremony">authentication ceremony</a>,
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredential-authenticatorattachment">authenticatorAttachment's</a> value is "cross-platform" and concurrently
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredential-isuserverifyingplatformauthenticatoravailable">isUserVerifyingPlatformAuthenticatorAvailable</a> returns true, then the user employed a
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#roaming-authenticators">roaming authenticator</a> for this <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#ceremony">ceremony</a> while there is an available
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#platform-authenticators">platform authenticator</a>. Thus the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> has the opportunity to prompt the user to register the
    ///         available <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#platform-authenticators">platform authenticator</a>, which may enable more streamlined user experience flows.
    ///     </para>
    ///     <para>
    ///         An <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator’s</a> <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator-attachment-modality">attachment modality</a> could change over time. For example, a mobile phone
    ///         might at one time only support <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#platform-attachment">platform attachment</a> but later receive updates to support
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#cross-platform-attachment">cross-platform attachment</a> as well.
    ///     </para>
    /// </remarks>
    [JsonPropertyName("authenticatorAttachment")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public AuthenticatorAttachment? AuthenticatorAttachment { get; }
}
