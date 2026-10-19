using System.Collections.Generic;
using WebAuthn.Net.Services.Metrics;

namespace WebAuthn.Net.DSL.Fakes;

public class FakeRegistrationCeremonyCounters : IRegistrationCeremonyCounters
{
    private readonly List<FakeAttestationStatementAnomaly> _attestationStatementAnomalies = new();

    public IReadOnlyList<FakeAttestationStatementAnomaly> AttestationStatementAnomalies => _attestationStatementAnomalies;

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

    public void IncrementAttestationStatementAnomaly(string fmt, string anomaly, bool tolerated)
    {
        _attestationStatementAnomalies.Add(new(fmt, anomaly, tolerated));
    }
}

public sealed record FakeAttestationStatementAnomaly(string Fmt, string Anomaly, bool Tolerated);
