using System.Collections.Generic;
using System.Text.Json;
using WebAuthn.Net.Models.Protocol.Enums;

namespace WebAuthn.Net.Models.Protocol.AuthenticationCeremony.VerifyAssertion;

/// <summary>
///     PublicKeyCredential. The response received from the authenticator during the authentication ceremony.
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://www.w3.org/TR/webauthn-3/#iface-pkcredential">Web Authentication: An API for accessing Public Key Credentials Level 3 - PublicKeyCredential Interface</a>
///     </para>
///     <para>
///         <a href="https://www.w3.org/TR/webauthn-3/#sctn-public-key-easy">Web Authentication: An API for accessing Public Key Credentials Level 3 - Easily accessing credential data</a>
///     </para>
/// </remarks>
public class AuthenticationResponse
{
    /// <summary>
    ///     Constructs <see cref="AuthenticationResponse" />.
    /// </summary>
    /// <param name="id">
    ///     <list type="bullet">
    ///         <item>
    ///             <term>
    ///                 <b>
    ///                     <a href="https://www.w3.org/TR/webauthn-3/#ref-for-dom-credential-id">WebAuthn</a>
    ///                 </b>
    ///             </term>
    ///             <description>
    ///                 This attribute is inherited from <a href="https://www.w3.org/TR/credential-management-1/#credential">Credential</a>, though <a href="https://www.w3.org/TR/webauthn-3/#publickeycredential">PublicKeyCredential</a> overrides
    ///                 <a href="https://www.w3.org/TR/credential-management-1/#credential">Credential’s getter</a>, instead returning the <a href="https://www.w3.org/TR/webauthn-3/#base64url-encoding">base64url encoding</a> of the data contained in the object’s
    ///                 <a href="https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-identifier-slot">[[identifier]]</a> <a href="https://tc39.es/ecma262/#sec-object-internal-methods-and-internal-slots">internal slot</a>.
    ///             </description>
    ///         </item>
    ///         <item>
    ///             <term>
    ///                 <b>
    ///                     <a href="https://www.w3.org/TR/credential-management-1/#dom-credential-id">Credential Management</a>
    ///                 </b>
    ///             </term>
    ///             <description>
    ///                 The credential’s identifier. The requirements for the identifier are distinct for each type of <a href="https://www.w3.org/TR/credential-management-1/#concept-credential">credential</a>. It might represent a username for username/password tuples, for example.
    ///             </description>
    ///         </item>
    ///     </list>
    /// </param>
    /// <param name="rawId">
    ///     This attribute returns the <a href="https://webidl.spec.whatwg.org/#idl-ArrayBuffer">ArrayBuffer</a> contained in the <a href="https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-identifier-slot">[[identifier]]</a> internal slot.
    /// </param>
    /// <param name="response">
    ///     This attribute contains the <a href="https://www.w3.org/TR/webauthn-3/#authenticator">authenticator’s</a> response to the client’s request to generate an <a href="https://www.w3.org/TR/webauthn-3/#authentication-assertion">authentication assertion</a>.
    /// </param>
    /// <param name="authenticatorAttachment">
    ///     This attribute reports the <a href="https://www.w3.org/TR/webauthn-3/#authenticator-attachment-modality">authenticator attachment modality</a> in effect at the time the
    ///     <a href="https://www.w3.org/TR/credential-management-1/#dom-credentialscontainer-get">navigator.credentials.get()</a> method successfully completes. The attribute’s value SHOULD be a member of
    ///     <a href="https://www.w3.org/TR/webauthn-3/#enumdef-authenticatorattachment">AuthenticatorAttachment</a>. <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Parties</a> SHOULD treat unknown values as if the value were null.
    /// </param>
    /// <param name="clientExtensionResults">
    ///     The value of <a href="https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-clientextensionsresults-slot">[[clientExtensionsResults]]</a>, which is a <a href="https://infra.spec.whatwg.org/#ordered-map">map</a> containing
    ///     <a href="https://www.w3.org/TR/webauthn-3/#extension-identifier">extension identifier</a> → <a href="https://www.w3.org/TR/webauthn-3/#client-extension-output">client extension output</a> entries produced by the extension’s
    ///     <a href="https://www.w3.org/TR/webauthn-3/#client-extension-processing">client extension processing</a>.
    /// </param>
    /// <param name="type">
    ///     This attribute’s getter returns the value of the object’s <a href="https://webidl.spec.whatwg.org/#dfn-interface-object">interface object's</a> <a href="https://www.w3.org/TR/credential-management-1/#dom-credential-type-slot">[[type]]</a> slot, which specifies the
    ///     <a href="https://www.w3.org/TR/credential-management-1/#credential-credential-type">credential type</a> represented by this object.
    /// </param>
    public AuthenticationResponse(
        byte[] id,
        byte[] rawId,
        AuthenticatorAssertionResponse response,
        AuthenticatorAttachment? authenticatorAttachment,
        Dictionary<string, JsonElement> clientExtensionResults,
        PublicKeyCredentialType type)
    {
        Id = id;
        RawId = rawId;
        Response = response;
        AuthenticatorAttachment = authenticatorAttachment;
        ClientExtensionResults = clientExtensionResults;
        Type = type;
    }

    /// <summary>
    ///     <list type="bullet">
    ///         <item>
    ///             <term>
    ///                 <b>
    ///                     <a href="https://www.w3.org/TR/webauthn-3/#ref-for-dom-credential-id">WebAuthn</a>
    ///                 </b>
    ///             </term>
    ///             <description>
    ///                 This attribute is inherited from <a href="https://www.w3.org/TR/credential-management-1/#credential">Credential</a>, though <a href="https://www.w3.org/TR/webauthn-3/#publickeycredential">PublicKeyCredential</a> overrides
    ///                 <a href="https://www.w3.org/TR/credential-management-1/#credential">Credential’s getter</a>, instead returning the <a href="https://www.w3.org/TR/webauthn-3/#base64url-encoding">base64url encoding</a> of the data contained in the object’s
    ///                 <a href="https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-identifier-slot">[[identifier]]</a> <a href="https://tc39.es/ecma262/#sec-object-internal-methods-and-internal-slots">internal slot</a>.
    ///             </description>
    ///         </item>
    ///         <item>
    ///             <term>
    ///                 <b>
    ///                     <a href="https://www.w3.org/TR/credential-management-1/#dom-credential-id">Credential Management</a>
    ///                 </b>
    ///             </term>
    ///             <description>
    ///                 The credential’s identifier. The requirements for the identifier are distinct for each type of <a href="https://www.w3.org/TR/credential-management-1/#concept-credential">credential</a>. It might represent a username for username/password tuples, for example.
    ///             </description>
    ///         </item>
    ///     </list>
    /// </summary>
    public byte[] Id { get; }

    /// <summary>
    ///     This attribute returns the <a href="https://webidl.spec.whatwg.org/#idl-ArrayBuffer">ArrayBuffer</a> contained in the <a href="https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-identifier-slot">[[identifier]]</a> internal slot.
    /// </summary>
    public byte[] RawId { get; }

    /// <summary>
    ///     This attribute contains the <a href="https://www.w3.org/TR/webauthn-3/#authenticator">authenticator’s</a> response to the client’s request to generate an <a href="https://www.w3.org/TR/webauthn-3/#authentication-assertion">authentication assertion</a>.
    /// </summary>
    public AuthenticatorAssertionResponse Response { get; }

    /// <summary>
    ///     This attribute reports the <a href="https://www.w3.org/TR/webauthn-3/#authenticator-attachment-modality">authenticator attachment modality</a> in effect at the time the
    ///     <a href="https://www.w3.org/TR/credential-management-1/#dom-credentialscontainer-get">navigator.credentials.get()</a> method successfully completes. The attribute’s value SHOULD be a member of
    ///     <a href="https://www.w3.org/TR/webauthn-3/#enumdef-authenticatorattachment">AuthenticatorAttachment</a>. <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Parties</a> SHOULD treat unknown values as if the value were null.
    /// </summary>
    /// <remarks>
    ///     <para>
    ///         If, as the result of an <a href="https://www.w3.org/TR/webauthn-3/#authentication-ceremony">authentication ceremony</a>, <a href="https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-authenticatorattachment">authenticatorAttachment’s</a> value is
    ///         <a href="https://www.w3.org/TR/webauthn-3/#dom-authenticatorattachment-cross-platform">"cross-platform"</a> and concurrently
    ///         <a href="https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-isuserverifyingplatformauthenticatoravailable">isUserVerifyingPlatformAuthenticatorAvailable</a> returns true, then the user employed a
    ///         <a href="https://www.w3.org/TR/webauthn-3/#roaming-authenticators">roaming authenticator</a> for this <a href="https://www.w3.org/TR/webauthn-3/#ceremony">ceremony</a> while there is an available
    ///         <a href="https://www.w3.org/TR/webauthn-3/#platform-authenticators">platform authenticator</a>. Thus the <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party</a> has the opportunity to prompt the user to register the available
    ///         <a href="https://www.w3.org/TR/webauthn-3/#platform-authenticators">platform authenticator</a>, which may enable more streamlined user experience flows.
    ///     </para>
    ///     <para>
    ///         An <a href="https://www.w3.org/TR/webauthn-3/#authenticator">authenticator’s</a> <a href="https://www.w3.org/TR/webauthn-3/#authenticator-attachment-modality">attachment modality</a> could change over time. For example, a mobile phone might at one time only support
    ///         <a href="https://www.w3.org/TR/webauthn-3/#platform-attachment">platform attachment</a> but later receive updates to support <a href="https://www.w3.org/TR/webauthn-3/#cross-platform-attachment">cross-platform attachment</a> as well.
    ///     </para>
    /// </remarks>
    public AuthenticatorAttachment? AuthenticatorAttachment { get; }

    /// <summary>
    ///     The value of <a href="https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-clientextensionsresults-slot">[[clientExtensionsResults]]</a>, which is a <a href="https://infra.spec.whatwg.org/#ordered-map">map</a> containing
    ///     <a href="https://www.w3.org/TR/webauthn-3/#extension-identifier">extension identifier</a> → <a href="https://www.w3.org/TR/webauthn-3/#client-extension-output">client extension output</a> entries produced by the extension’s
    ///     <a href="https://www.w3.org/TR/webauthn-3/#client-extension-processing">client extension processing</a>.
    /// </summary>
    public Dictionary<string, JsonElement> ClientExtensionResults { get; }

    /// <summary>
    ///     This attribute’s getter returns the value of the object’s <a href="https://webidl.spec.whatwg.org/#dfn-interface-object">interface object's</a> <a href="https://www.w3.org/TR/credential-management-1/#dom-credential-type-slot">[[type]]</a> slot, which specifies the
    ///     <a href="https://www.w3.org/TR/credential-management-1/#credential-credential-type">credential type</a> represented by this object.
    /// </summary>
    public PublicKeyCredentialType Type { get; }
}
