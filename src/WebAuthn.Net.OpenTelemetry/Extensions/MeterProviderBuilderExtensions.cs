using System;
using OpenTelemetry.Metrics;
using WebAuthn.Net.Services.Metrics.Implementation.Constants;

namespace WebAuthn.Net.OpenTelemetry.Extensions;

public static class MeterProviderBuilderExtensions
{
    public static MeterProviderBuilder AddWebAuthn(this MeterProviderBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.AddMeter(Meters.RegistrationCeremonyMeterName);
        builder.AddMeter(Meters.AuthenticationCeremonyMeterName);
        return builder;
    }
}
