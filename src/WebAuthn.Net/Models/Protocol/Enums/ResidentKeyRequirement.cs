using System.Runtime.Serialization;

namespace WebAuthn.Net.Models.Protocol.Enums;

/// <summary>
///     Resident Key Requirement Enumeration.
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#enum-residentKeyRequirement">Web Authentication: An API for accessing Public Key Credentials Level 3 - §5.4.6. Resident Key Requirement Enumeration </a>
///     </para>
///     <para>
///         The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> can seek information on whether or not the authenticator created a
///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client-side-discoverable-credential">client-side discoverable credential</a> using the
///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credentialpropertiesoutput-resident-key-credential-property">resident key credential property</a> of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credprops">Credential Properties Extension</a>
///         . This is useful when values of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-residentkeyrequirement-discouraged">discouraged</a> or <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-residentkeyrequirement-preferred">preferred</a> are used
///         for options.<a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialcreationoptions-authenticatorselection">authenticatorSelection</a>.
///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorselectioncriteria-residentkey">residentKey</a>, because in those cases it is possible for an <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a> to
///         create either a <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client-side-discoverable-credential">client-side discoverable credential</a> or a <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#server-side-credential">server-side credential</a>.
///     </para>
/// </remarks>
public enum ResidentKeyRequirement
{
    /// <summary>
    ///     The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> prefers creating a <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#server-side-credential">server-side credential</a>, but will accept a
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client-side-discoverable-credential">client-side discoverable credential</a>. The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client">client</a> and
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a> SHOULD create a <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#server-side-credential">server-side credential</a> if possible.
    /// </summary>
    /// <remarks>
    ///     A <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> cannot require that a created credential is a <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#server-side-credential">server-side credential</a> and the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credprops">Credential Properties Extension</a> may not return a value for the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-credentialpropertiesoutput-rk">rk</a> property. Because of this, it may
    ///     be the case that it does not know if a credential is a <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#server-side-credential">server-side credential</a> or not and thus does not know whether creating a second credential with the same
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-handle">user handle</a> will evict the first.
    /// </remarks>
    [EnumMember(Value = "discouraged")]
    Discouraged = 0,

    /// <summary>
    ///     The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> strongly prefers creating a <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client-side-discoverable-credential">client-side discoverable credential</a>, but will
    ///     accept a <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#server-side-credential">server-side credential</a>. The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client">client</a> and
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a> SHOULD create a <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#discoverable-credential">discoverable credential</a> if possible. For example, the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client">client</a> SHOULD guide the user through setting up <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-verification">user verification</a> if needed to create a
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#discoverable-credential">discoverable credential</a>. This takes precedence over the setting of
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorselectioncriteria-userverification">userVerification</a>.
    /// </summary>
    [EnumMember(Value = "preferred")]
    Preferred = 1,

    /// <summary>
    ///     The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> requires a <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client-side-discoverable-credential">client-side discoverable credential</a>. The
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client">client</a> MUST return an error if a <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client-side-discoverable-credential">client-side discoverable credential</a> cannot be created.
    /// </summary>
    [EnumMember(Value = "required")]
    Required = 2
}
