using System.Runtime.Serialization;

namespace WebAuthn.Net.Models.Protocol.Enums;

/// <summary>
///     <para>Authenticator Attachment Enumeration</para>
///     <para>
///         This enumeration's values describe <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticators'</a> <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator-attachment-modality">attachment modalities</a>.
///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Parties</a> use this to express a preferred <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator-attachment-modality">authenticator attachment modality</a> when
///         calling <a href="https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-create">navigator.credentials.create()</a> to <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-createCredential">create a credential</a>, and
///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client">clients</a> use this to report the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator-attachment-modality">authenticator attachment modality</a> used to complete a
///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#registration-ceremony">registration</a> or <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authentication-ceremony">authentication ceremony</a>.
///     </para>
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#enum-attachment">Web Authentication: An API for accessing Public Key Credentials Level 3 - §5.4.5. Authenticator Attachment Enumeration</a>
///     </para>
///     <para>
///         An <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator-attachment-modality">authenticator attachment modality</a> selection option is available only in the
///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredential-create-slot">[[Create]](origin, options, sameOriginWithAncestors)</a> operation. The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> may use
///         it to, for example, ensure the user has a <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#roaming-credential">roaming credential</a> for authenticating on another <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client-device">client device</a>; or
///         to specifically register a <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#platform-credential">platform credential</a> for easier reauthentication using a particular <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client-device">client device</a>
///         . The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredential-discoverfromexternalsource-slot">[[DiscoverFromExternalSource]](origin, options, sameOriginWithAncestors)</a> operation has no
///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator-attachment-modality">authenticator attachment modality</a> selection option, so the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> SHOULD accept any of
///         the user's registered <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential">credentials</a>. The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client">client</a> and user will then use whichever is available and convenient at
///         the time.
///     </para>
/// </remarks>
public enum AuthenticatorAttachment
{
    /// <summary>
    ///     This value indicates <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#platform-attachment">platform attachment</a>.
    /// </summary>
    [EnumMember(Value = "platform")]
    Platform = 0,

    /// <summary>
    ///     This value indicates <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#cross-platform-attachment">cross-platform attachment</a>.
    /// </summary>
    [EnumMember(Value = "cross-platform")]
    CrossPlatform = 1
}
