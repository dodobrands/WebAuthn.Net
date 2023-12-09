using System;
using System.Diagnostics.Metrics;
using WebAuthn.Net.Services.Metrics.Models;

namespace WebAuthn.Net.Services.Metrics.Implementation;

public class AuthenticationCeremonyCounters : IIncrementMetricsCounter<AuthenticationCeremonyCounter>
{
    private readonly Counter<int> _beginAuthenticationCeremonyCounter;
    private readonly Counter<int> _completeAuthenticationCeremonyCounter;
    private readonly Counter<int> _failedAuthenticationCeremonyCounter;

    public AuthenticationCeremonyCounters(Counter<int> beginAuthenticationCeremonyCounter, Counter<int> failedAuthenticationCeremonyCounter, Counter<int> completeAuthenticationCeremonyCounter)
    {
        _beginAuthenticationCeremonyCounter = beginAuthenticationCeremonyCounter;
        _failedAuthenticationCeremonyCounter = failedAuthenticationCeremonyCounter;
        _completeAuthenticationCeremonyCounter = completeAuthenticationCeremonyCounter;
    }

    public void Increment(AuthenticationCeremonyCounter counter)
    {
        switch (counter)
        {
            case AuthenticationCeremonyCounter.Begin:
                _beginAuthenticationCeremonyCounter.Add(1);
                break;
            case AuthenticationCeremonyCounter.Complete:
                _completeAuthenticationCeremonyCounter.Add(1);
                break;
            case AuthenticationCeremonyCounter.Failed:
                _failedAuthenticationCeremonyCounter.Add(1);
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(counter), counter, null);
        }
    }
}
