## WebAuthn.Net.OpenTelemetry

This project contains extensions for integrating WebAuthn.Net metrics with [OpenTelemetry](https://opentelemetry.io)

### Quickstart

To pass WebAuth.Net metrics to OpenTelemetry, you need to call the corresponding extension method for `MeterProviderBuilder`:

```csharp
services.AddOpenTelemetry()
    .WithMetrics(metrics =>
    {
        metrics.AddWebAuthnNet();
    });
```

Remember, to read metrics you will need the corresponding exporter (but this topic is beyond the scope of this project).
