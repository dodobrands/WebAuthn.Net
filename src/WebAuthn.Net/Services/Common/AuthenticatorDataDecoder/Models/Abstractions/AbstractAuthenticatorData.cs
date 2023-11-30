using WebAuthn.Net.Services.Common.AuthenticatorDataDecoder.Models.Enums;

namespace WebAuthn.Net.Services.Common.AuthenticatorDataDecoder.Models.Abstractions;

/// <summary>
///     Authenticator Data.
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-authenticator-data">Web Authentication: An API for accessing Public Key Credentials Level 3 - §6.1. Authenticator Data</a>
///     </para>
///     <para>
///         It MUST be present in an authenticator data resulting from a <a href="https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-get">get()</a> operation if, and only if, the
///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorassertionresponse-attestationobject">attestationObject</a> attribute is present in the assertion result.
///     </para>
/// </remarks>
public abstract class AbstractAuthenticatorData
{
    /// <summary>
    ///     Raw <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-authenticator-data">authenticator data</a> value.
    /// </summary>
    public abstract byte[] Raw { get; }

    /// <summary>
    ///     SHA-256 hash of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#rp-id">RP ID</a> the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential">credential</a> is
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#scope">scoped</a> to.
    /// </summary>
    public abstract byte[] RpIdHash { get; }

    /// <summary>
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-authenticator-data">Authenticator data</a> <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-flags">flags</a>.
    /// </summary>
    public abstract AuthenticatorDataFlags Flags { get; }

    /// <summary>
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#signature-counter">Signature counter</a>, 32-bit unsigned integer.
    /// </summary>
    public abstract uint SignCount { get; }
}
