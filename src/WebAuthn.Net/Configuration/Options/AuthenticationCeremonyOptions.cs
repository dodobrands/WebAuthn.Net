using System.Diagnostics.CodeAnalysis;

namespace WebAuthn.Net.Configuration.Options;

/// <summary>
///     Options that define the behavior of the authentication ceremony.
/// </summary>
[SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
[SuppressMessage("ReSharper", "AutoPropertyCanBeMadeGetOnly.Global")]
public class AuthenticationCeremonyOptions
{
    /// <summary>
    ///     The default timeout for the ceremony execution if it was not specified in the request when initiating the authentication ceremony. Specified in milliseconds. The default is 300000 milliseconds (5 minutes).
    /// </summary>
    public uint DefaultTimeout { get; set; } = 300_000;

    /// <summary>
    ///     <para>
    ///         Whether the authentication ceremony fails when the signature counter of the authenticator data ('authData.signCount') is less than or equal to the one stored in the credential record, although at least one of them is nonzero.
    ///         This is a signal, but not proof, that the authenticator may be cloned (<a href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion">WebAuthn Level 3, §7.2, step 22</a>). Defaults to <see langword="true" />.
    ///     </para>
    ///     <para>
    ///         If <see langword="false" />, such a ceremony completes with <see cref="Services.AuthenticationCeremony.Models.VerifyAssertion.CompleteAuthenticationCeremonyResult.SignCountNotIncreased" /> set to <see langword="true" />,
    ///         and the stored signature counter keeps its value, so the next assertions are compared with the highest one.
    ///     </para>
    /// </summary>
    public bool AbortCeremonyWhenSignCountIsLessOrEqualStoredValue { get; set; } = true;
}
