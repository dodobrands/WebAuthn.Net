using System.Diagnostics.Metrics;
using NUnit.Framework;
using WebAuthn.Net.DSL;

namespace WebAuthn.Net.Services.Metrics.Implementation;

// The names of the instruments and their tags are the contract with the dashboards and the alerts, so they are verified on the recorded measurements.
public class DefaultAuthenticationCeremonyCountersTests
{
    private static readonly RecordedMeasurement[] ExpectedResponseAnomalyMeasurements =
    {
        new("webauthn.authn.response.anomalies", 1, "anomaly=sign_count.not_increased,outcome=tolerated"),
        new("webauthn.authn.response.anomalies", 1, "anomaly=sign_count.not_increased,outcome=rejected")
    };

    [Test]
    public void ResponseAnomaly_IsRecordedWithAnomalyAndOutcome()
    {
        using var counters = new ObservableAuthenticationCeremonyCounters();
        using var recorder = new MeterRecorder(counters.ObservedMeter);

        counters.IncrementResponseAnomaly("sign_count.not_increased", true);
        counters.IncrementResponseAnomaly("sign_count.not_increased", false);

        Assert.That(recorder.Measurements, Is.EqualTo(ExpectedResponseAnomalyMeasurements));
    }

    private sealed class ObservableAuthenticationCeremonyCounters : DefaultAuthenticationCeremonyCounters
    {
        public Meter ObservedMeter => Meter;
    }
}
