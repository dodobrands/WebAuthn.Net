using System.Diagnostics.Metrics;

namespace WebAuthn.Net.Services.Metrics.Implementation.Constants;

/// <summary>
///     Constants of <see cref="Meter" /> used in metrics.
/// </summary>
public static class Meters
{
    /// <summary>
    ///     Name of the <see cref="Meter" /> responsible  for creating and tracking Instruments of the authentication ceremony.
    /// </summary>
    public const string AuthenticationCeremonyMeterName = "WebAuthn.Net.AuthenticationCeremony";

    /// <summary>
    ///     Name of the <see cref="Meter" /> responsible  for creating and tracking Instruments of the registration ceremony.
    /// </summary>
    public const string RegistrationCeremonyMeterName = "WebAuthn.Net.RegistrationCeremony";
}
