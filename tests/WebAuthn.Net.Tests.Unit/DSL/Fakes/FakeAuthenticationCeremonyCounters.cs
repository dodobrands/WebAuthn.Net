using System.Collections.Generic;
using WebAuthn.Net.Services.Metrics;

namespace WebAuthn.Net.DSL.Fakes;

public class FakeAuthenticationCeremonyCounters : IAuthenticationCeremonyCounters
{
    private readonly List<FakeResponseAnomaly> _responseAnomalies = new();

    public IReadOnlyList<FakeResponseAnomaly> ResponseAnomalies => _responseAnomalies;

    public void IncrementBeginCeremonyStart()
    {
    }

    public void IncrementBeginCeremonyEnd(bool successful)
    {
    }

    public void IncrementCompleteCeremonyStart()
    {
    }

    public void IncrementCompleteCeremonyEnd(bool successful)
    {
    }

    public void IncrementResponseAnomaly(string anomaly, bool tolerated)
    {
        _responseAnomalies.Add(new(anomaly, tolerated));
    }
}
