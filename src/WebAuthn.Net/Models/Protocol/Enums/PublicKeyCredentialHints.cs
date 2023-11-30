using System.Runtime.Serialization;

namespace WebAuthn.Net.Models.Protocol.Enums;

/// <summary>
///     User-agent Hints Enumeration
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#enum-hints">Web Authentication: An API for accessing Public Key Credentials Level 3 - §5.8.7. User-agent Hints Enumeration</a>
///     </para>
///     <para>
///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#webauthn-relying-party">WebAuthn Relying Parties</a> may use this enumeration to communicate hints to the user-agent about how a request may be best completed. These hints are not requirements, and do not bind
///         the user-agent, but may guide it in providing the best experience by using contextual information that the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> has about the request. Hints are provided in order of decreasing
///         preference so, if two hints are contradictory, the first one controls. Hints may also overlap: if a more-specific hint is defined a <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> may still wish to send less specific ones for
///         user-agents that may not recognise the more specific one. In this case the most specific hint should be sent before the less-specific ones.
///     </para>
///     <para>
///         Hints MAY contradict information contained in credential <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialdescriptor-transports">transports</a> and
///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorselectioncriteria-authenticatorattachment">authenticatorAttachment</a>. When this occurs, the hints take precedence. (Note that
///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialdescriptor-transports">transports</a> values are not provided when using <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#discoverable-credential">discoverable</a> credentials,
///         leaving hints as the only avenue for expressing some aspects of such a request.)
///     </para>
/// </remarks>
public enum PublicKeyCredentialHints
{
    /// <summary>
    ///     <para>
    ///         Indicates that the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> believes that users will satisfy this request with a physical security key. For example, an enterprise
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> may set this hint if they have issued security keys to their employees and will only accept those
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticators</a> for <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#registration-ceremony">registration</a> and
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authentication-ceremony">authentication</a>.
    ///     </para>
    ///     <para>
    ///         For compatibility with older user agents, when this hint is used in <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dictdef-publickeycredentialcreationoptions">PublicKeyCredentialCreationOptions</a>, the
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorselectioncriteria-authenticatorattachment">authenticatorAttachment</a> SHOULD be set to
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorattachment-cross-platform">cross-platform</a>.
    ///     </para>
    /// </summary>
    [EnumMember(Value = "security-key")]
    SecurityKey = 0,

    /// <summary>
    ///     <para>
    ///         Indicates that the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> believes that users will satisfy this request with a
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#platform-authenticators">platform authenticator</a> attached to the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client-device">client device</a>.
    ///     </para>
    ///     <para>
    ///         For compatibility with older user agents, when this hint is used in <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dictdef-publickeycredentialcreationoptions">PublicKeyCredentialCreationOptions</a>, the
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorselectioncriteria-authenticatorattachment">authenticatorAttachment</a> SHOULD be set to
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorattachment-platform">platform</a>.
    ///     </para>
    /// </summary>
    [EnumMember(Value = "client-device")]
    ClientDevice = 1,

    /// <summary>
    ///     <para>
    ///         Indicates that the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> believes that users will satisfy this request with general-purpose
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticators</a> such as smartphones. For example, a consumer <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> may believe that only a small fraction
    ///         of their customers possesses dedicated security keys. This option also implies that the local <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#platform-authenticators">platform authenticator</a> should not be promoted in the UI.
    ///     </para>
    ///     <para>
    ///         For compatibility with older user agents, when this hint is used in <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dictdef-publickeycredentialcreationoptions">PublicKeyCredentialCreationOptions</a>, the
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorselectioncriteria-authenticatorattachment">authenticatorAttachment</a> SHOULD be set to
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorattachment-cross-platform">cross-platform</a>.
    ///     </para>
    /// </summary>
    [EnumMember(Value = "hybrid")]
    Hybrid = 2
}
