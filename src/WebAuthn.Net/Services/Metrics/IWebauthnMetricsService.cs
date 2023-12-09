using WebAuthn.Net.Services.Metrics.Models;

namespace WebAuthn.Net.Services.Metrics;

public interface IWebauthnMetricsService
{
    IIncrementMetricsCounter<AuthenticationCeremonyCounter> AuthenticationCeremony();
    IIncrementMetricsCounter<RegistrationCeremonyCounter> RegistrationCeremony();
}
