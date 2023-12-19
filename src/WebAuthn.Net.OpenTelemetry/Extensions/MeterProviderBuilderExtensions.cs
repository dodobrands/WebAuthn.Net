using System;
using OpenTelemetry.Metrics;
using WebAuthn.Net.Services.Metrics.Implementation.Constants;

namespace WebAuthn.Net.OpenTelemetry.Extensions;

/// <summary>
///     Extension methods for <see cref="MeterProviderBuilder" />.
/// </summary>
public static class MeterProviderBuilderExtensions
{
    /// <summary>
    ///     Adds WebAuthn.Net metrics to the <see cref="MeterProviderBuilder" />
    /// </summary>
    /// <param name="builder">Extensible instance of <see cref="MeterProviderBuilder" /></param>
    /// <returns>Configured <see cref="MeterProviderBuilder" />.</returns>
    public static MeterProviderBuilder AddWebAuthnNet(this MeterProviderBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.AddMeter(Meters.RegistrationCeremonyMeterName);
        builder.AddMeter(Meters.AuthenticationCeremonyMeterName);
        return builder;
    }
}
