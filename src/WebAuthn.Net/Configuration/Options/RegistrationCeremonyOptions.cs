using System.Diagnostics.CodeAnalysis;

namespace WebAuthn.Net.Configuration.Options;

/// <summary>
///     Options that define the behavior of the registration ceremony.
/// </summary>
[SuppressMessage("ReSharper", "AutoPropertyCanBeMadeGetOnly.Global")]
public class RegistrationCeremonyOptions
{
    /// <summary>
    ///     The default timeout for the ceremony execution if it was not specified in the request when initiating the registration ceremony. Specified in milliseconds. The default is 300000 milliseconds (5 minutes).
    /// </summary>
    public uint DefaultTimeout { get; set; } = 300_000;
}
