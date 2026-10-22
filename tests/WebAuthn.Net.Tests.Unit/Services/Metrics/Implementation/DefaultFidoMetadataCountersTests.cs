using System.Diagnostics.Metrics;
using NUnit.Framework;
using WebAuthn.Net.DSL;

namespace WebAuthn.Net.Services.Metrics.Implementation;

// The names of the instruments and their tags are the contract with the dashboards and the alerts, so they are verified on the recorded measurements.
public class DefaultFidoMetadataCountersTests
{
    private static readonly RecordedMeasurement[] ExpectedDownloadMeasurements =
    {
        new("webauthn.mds.download.start", 1, ""),
        new("webauthn.mds.download.failures", 1, "reason=chain_invalid"),
        new("webauthn.mds.download.end", 1, "status=fail"),
        new("webauthn.mds.download.start", 1, ""),
        new("webauthn.mds.download.end", 1, "status=ok")
    };

    private static readonly RecordedMeasurement[] ExpectedValueIgnoredMeasurements =
    {
        new("webauthn.mds.decode.values.ignored", 1, "member=nextUpdate")
    };

    private static readonly RecordedMeasurement[] ExpectedLookupWithoutMetadataMeasurements =
    {
        new("webauthn.mds.search.no_metadata", 1, "")
    };

    [Test]
    public void Download_IsRecordedWithStatusAndFailureReason()
    {
        using var counters = new ObservableFidoMetadataCounters();
        using var recorder = new MeterRecorder(counters.ObservedMeter);

        counters.IncrementDownloadStart();
        counters.IncrementDownloadFailure("chain_invalid");
        counters.IncrementDownloadEnd(false);
        counters.IncrementDownloadStart();
        counters.IncrementDownloadEnd(true);

        Assert.That(recorder.Measurements, Is.EqualTo(ExpectedDownloadMeasurements));
    }

    [Test]
    public void ValueIgnored_IsRecordedWithMember()
    {
        using var counters = new ObservableFidoMetadataCounters();
        using var recorder = new MeterRecorder(counters.ObservedMeter);

        counters.IncrementValueIgnored("nextUpdate");

        Assert.That(recorder.Measurements, Is.EqualTo(ExpectedValueIgnoredMeasurements));
    }

    [Test]
    public void LookupWithoutMetadata_IsRecorded()
    {
        using var counters = new ObservableFidoMetadataCounters();
        using var recorder = new MeterRecorder(counters.ObservedMeter);

        counters.IncrementLookupWithoutMetadata();

        Assert.That(recorder.Measurements, Is.EqualTo(ExpectedLookupWithoutMetadataMeasurements));
    }

    private sealed class ObservableFidoMetadataCounters : DefaultFidoMetadataCounters
    {
        public Meter ObservedMeter => Meter;
    }
}
