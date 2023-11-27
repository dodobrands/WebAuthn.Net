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
    ///     A flag that defines behavior in a situation where the stored SignCount for a credential is greater than or equal to the one sent during the ceremony. Defaults to <see langword="true" />.
    /// </summary>
    public bool AbortCeremonyWhenSignCountIsLessOrEqualStoredValue { get; set; } = true;
}
