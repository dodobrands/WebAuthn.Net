using System;
using System.Diagnostics.Metrics;
using WebAuthn.Net.Services.Metrics.Models;

namespace WebAuthn.Net.Services.Metrics.Implementation;

public class RegistrationCeremonyCounters : IIncrementMetricsCounter<RegistrationCeremonyCounter>
{
    private readonly Counter<int> _beginRegistrationCeremonyCounter;
    private readonly Counter<int> _completeRegistrationCeremonyCounter;
    private readonly Counter<int> _failedRegistrationCeremonyCounter;

    public RegistrationCeremonyCounters(Counter<int> beginRegistrationCeremonyCounter, Counter<int> failedRegistrationCeremonyCounter, Counter<int> completeRegistrationCeremonyCounter)
    {
        _beginRegistrationCeremonyCounter = beginRegistrationCeremonyCounter;
        _failedRegistrationCeremonyCounter = failedRegistrationCeremonyCounter;
        _completeRegistrationCeremonyCounter = completeRegistrationCeremonyCounter;
    }

    public void Increment(RegistrationCeremonyCounter counter)
    {
        switch (counter)
        {
            case RegistrationCeremonyCounter.Begin:
                _beginRegistrationCeremonyCounter.Add(1);
                break;
            case RegistrationCeremonyCounter.Complete:
                _completeRegistrationCeremonyCounter.Add(1);
                break;
            case RegistrationCeremonyCounter.Failed:
                _failedRegistrationCeremonyCounter.Add(1);
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(counter), counter, null);
        }
    }
}
