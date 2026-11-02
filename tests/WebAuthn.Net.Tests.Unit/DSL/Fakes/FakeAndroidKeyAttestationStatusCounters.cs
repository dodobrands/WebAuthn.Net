using System.Collections.Generic;
using WebAuthn.Net.Services.Metrics;

namespace WebAuthn.Net.DSL.Fakes;

public class FakeAndroidKeyAttestationStatusCounters : IAndroidKeyAttestationStatusCounters
{
    private readonly List<(string Anomaly, bool Tolerated)> _decodeAnomalies = new();
    private readonly List<string> _downloadFailures = new();
    private readonly List<string> _embeddedFailures = new();
    private readonly List<string> _ingestExceptions = new();

    public IReadOnlyList<string> DownloadFailures => _downloadFailures;

    public IReadOnlyList<string> EmbeddedFailures => _embeddedFailures;

    public IReadOnlyList<string> IngestExceptions => _ingestExceptions;

    public IReadOnlyList<(string Anomaly, bool Tolerated)> DecodeAnomalies => _decodeAnomalies;

    public int ChecksWithoutStatusList { get; private set; }

    public int CertificatesListed { get; private set; }

    public void IncrementDownloadFailure(string reason)
    {
        _downloadFailures.Add(reason);
    }

    public void IncrementEmbeddedFailure(string reason)
    {
        _embeddedFailures.Add(reason);
    }

    public void IncrementIngestException(string source)
    {
        _ingestExceptions.Add(source);
    }

    public void IncrementDecodeAnomaly(string anomaly, bool tolerated)
    {
        _decodeAnomalies.Add((anomaly, tolerated));
    }

    public void IncrementCheckWithoutStatusList()
    {
        ChecksWithoutStatusList++;
    }

    public void IncrementCertificateListed()
    {
        CertificatesListed++;
    }
}
