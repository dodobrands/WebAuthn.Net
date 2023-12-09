using System.Diagnostics.Metrics;
using WebAuthn.Net.Services.Metrics.Models;

namespace WebAuthn.Net.Services.Metrics.Implementation;

public class WebauthnMetricsService : IWebauthnMetricsService
{
    private readonly AuthenticationCeremonyCounters _authenticationCeremonyCounters;
    private readonly Meter _meter = new("WebAuthn.Net", "1.0.0");
    private readonly RegistrationCeremonyCounters _registrationCeremonyCounters;

    public WebauthnMetricsService()
    {
        _authenticationCeremonyCounters = new(
            _meter.CreateCounter<int>("authentication-ceremony-begin", description: "Number of initiated authentication ceremonies"),
            _meter.CreateCounter<int>("authentication-ceremony-failed", description: "Number of failed authentication ceremonies"),
            _meter.CreateCounter<int>("authentication-ceremony-complete", description: "Number of completed authentication ceremonies")
        );
        _registrationCeremonyCounters = new(
            _meter.CreateCounter<int>("registration-ceremony-begin", description: "Number of initiated registration ceremonies"),
            _meter.CreateCounter<int>("registration-ceremony-failed", description: "Number of failed registration ceremonies"),
            _meter.CreateCounter<int>("registration-ceremony-complete", description: "Number of completed registration ceremonies")
        );
    }

    public IIncrementMetricsCounter<AuthenticationCeremonyCounter> AuthenticationCeremony()
    {
        return _authenticationCeremonyCounters;
    }

    public IIncrementMetricsCounter<RegistrationCeremonyCounter> RegistrationCeremony()
    {
        return _registrationCeremonyCounters;
    }
}
