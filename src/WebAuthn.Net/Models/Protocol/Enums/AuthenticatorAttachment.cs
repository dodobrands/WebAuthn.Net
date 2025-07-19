using System.Runtime.Serialization;

namespace WebAuthn.Net.Models.Protocol.Enums;

/// <summary>
///     <para>Authenticator Attachment Enumeration</para>
///     <para>
///         This enumeration’s values describe <a href="https://www.w3.org/TR/webauthn-3/#authenticator">authenticators'</a> <a href="https://www.w3.org/TR/webauthn-3/#authenticator-attachment-modality">attachment modalities</a>.
///         <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Parties</a> use this to express a preferred <a href="https://www.w3.org/TR/webauthn-3/#authenticator-attachment-modality">authenticator attachment modality</a> when calling
///         <a href="https://www.w3.org/TR/credential-management-1/#dom-credentialscontainer-create">navigator.credentials.create()</a> to <a href="https://www.w3.org/TR/webauthn-3/#sctn-createCredential">create a credential</a>, and
///         <a href="https://www.w3.org/TR/webauthn-3/#client">clients</a> use this to report the <a href="https://www.w3.org/TR/webauthn-3/#authenticator-attachment-modality">authenticator attachment modality</a> used to complete a
///         <a href="https://www.w3.org/TR/webauthn-3/#registration-ceremony">registration</a> or <a href="https://www.w3.org/TR/webauthn-3/#authentication-ceremony">authentication</a> ceremony.
///     </para>
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://www.w3.org/TR/webauthn-3/#enum-attachment">Web Authentication: An API for accessing Public Key Credentials Level 3 - Authenticator Attachment Enumeration (enum AuthenticatorAttachment)</a>
///     </para>
///     <para>
///         An <a href="https://www.w3.org/TR/webauthn-3/#authenticator-attachment-modality">authenticator attachment modality</a> selection option is available only in the
///         <a href="https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-create-slot">[[Create]](origin, options, sameOriginWithAncestors)</a> operation. The <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party</a> may use it to, for example, ensure the user
///         has a <a href="https://www.w3.org/TR/webauthn-3/#roaming-credential">roaming credential</a> for authenticating on another <a href="https://www.w3.org/TR/webauthn-3/#client-device">client device</a>; or to specifically register a
///         <a href="https://www.w3.org/TR/webauthn-3/#platform-credential">platform credential</a> for easier reauthentication using a particular <a href="https://www.w3.org/TR/webauthn-3/#client-device">client device</a>. The
///         <a href="https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-discoverfromexternalsource-slot">[[DiscoverFromExternalSource]](origin, options, sameOriginWithAncestors)</a> operation has no
///         <a href="https://www.w3.org/TR/webauthn-3/#authenticator-attachment-modality">authenticator attachment modality</a> selection option. The <a href="https://www.w3.org/TR/webauthn-3/#client">client</a> and user will use whichever
///         <a href="https://www.w3.org/TR/credential-management-1/#concept-credential">credential</a> is available and convenient at the time, subject to the <a href="https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialrequestoptions-allowcredentials">allowCredentials</a>
///         option.
///     </para>
/// </remarks>
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
