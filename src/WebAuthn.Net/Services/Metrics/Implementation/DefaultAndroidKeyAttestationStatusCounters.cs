using System;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using WebAuthn.Net.Services.Metrics.Implementation.Constants;

namespace WebAuthn.Net.Services.Metrics.Implementation;

/// <summary>
///     Default implementation of <see cref="IAndroidKeyAttestationStatusCounters" />.
/// </summary>
public class DefaultAndroidKeyAttestationStatusCounters : IAndroidKeyAttestationStatusCounters, IDisposable
{
    /// <summary>
    ///     Constructs <see cref="DefaultAndroidKeyAttestationStatusCounters" />.
    /// </summary>
    public DefaultAndroidKeyAttestationStatusCounters()
    {
        Meter = new(Meters.AndroidKeyAttestationStatusMeterName);
        DownloadFailuresCounter = Meter.CreateCounter<long>(
            "webauthn.android_key.status_list.download.failures",
            null,
            "The number of certificate revocation status lists of the Android attestation keys that could not be downloaded, or were rejected after the download because they are malformed");
        EmbeddedFailuresCounter = Meter.CreateCounter<long>(
            "webauthn.android_key.status_list.embedded.failures",
            null,
            "The number of certificate revocation status lists of the Android attestation keys embedded in the application that could not be loaded, or were rejected because they are malformed");
        IngestExceptionsCounter = Meter.CreateCounter<long>(
            "webauthn.android_key.status_list.ingest.exceptions",
            null,
            "The number of attempts to load and store the certificate revocation status list of the Android attestation keys (embedded in the application or downloaded) that ended with an unexpected exception");
        DecodeAnomaliesCounter = Meter.CreateCounter<long>(
            "webauthn.android_key.status_list.decode.anomalies",
            null,
            "The number of anomalies found in the entries of the certificate revocation status list of the Android attestation keys during decoding");
        ChecksWithoutStatusListCounter = Meter.CreateCounter<long>(
            "webauthn.android_key.status_list.check.no_list",
            null,
            "The number of attestation statements whose certificate chain ends at a root certificate of the key attestation of Google that were rejected because no certificate revocation status list of the Android attestation keys is available (for example, before the first successful download)");
        CertificatesListedCounter = Meter.CreateCounter<long>(
            "webauthn.android_key.status_list.check.listed",
            null,
            "The number of attestation statements whose certificate chain ends at a root certificate of the key attestation of Google that were rejected because a certificate of the chain is in the certificate revocation status list of the Android attestation keys");
    }

    /// <summary>
    ///     <see cref="Meter" /> responsible for creating and tracking Instruments of the certificate revocation status list of the Android attestation keys.
    /// </summary>
    protected Meter Meter { get; }

    /// <summary>
    ///     Counter of the status lists that could not be downloaded, or were rejected after the download because they are malformed.
    /// </summary>
    protected Counter<long> DownloadFailuresCounter { get; }

    /// <summary>
    ///     Counter of the status lists embedded in the application that could not be loaded, or were rejected because they are malformed.
    /// </summary>
    protected Counter<long> EmbeddedFailuresCounter { get; }

    /// <summary>
    ///     Counter of the attempts to load and store the status list that ended with an unexpected exception.
    /// </summary>
    protected Counter<long> IngestExceptionsCounter { get; }

    /// <summary>
    ///     Counter of the anomalies found in the entries of the status list during decoding.
    /// </summary>
    protected Counter<long> DecodeAnomaliesCounter { get; }

    /// <summary>
    ///     Counter of the attestation statements whose certificate chain ends at a root certificate of the key attestation of Google that were rejected because no status list is available.
    /// </summary>
    protected Counter<long> ChecksWithoutStatusListCounter { get; }

    /// <summary>
    ///     Counter of the attestation statements whose certificate chain ends at a root certificate of the key attestation of Google that were rejected because a certificate of the chain is in the status list.
    /// </summary>
    protected Counter<long> CertificatesListedCounter { get; }

    /// <inheritdoc />
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <inheritdoc />
    public virtual void IncrementDownloadFailure(string reason)
    {
        DownloadFailuresCounter.Add(
            1L,
            new TagList
            {
                new(Tags.Reason, reason)
            });
    }

    /// <inheritdoc />
    public virtual void IncrementEmbeddedFailure(string reason)
    {
        EmbeddedFailuresCounter.Add(
            1L,
            new TagList
            {
                new(Tags.Reason, reason)
            });
    }

    /// <inheritdoc />
    public virtual void IncrementIngestException(string source)
    {
        IngestExceptionsCounter.Add(
            1L,
            new TagList
            {
                new(Tags.Source, source)
            });
    }

    /// <inheritdoc />
    public virtual void IncrementDecodeAnomaly(string anomaly, bool tolerated)
    {
        var outcome = tolerated
            ? TagValues.OutcomeTolerated
            : TagValues.OutcomeRejected;
        DecodeAnomaliesCounter.Add(
            1L,
            new TagList
            {
                new(Tags.Anomaly, anomaly),
                new(Tags.Outcome, outcome)
            });
    }

    /// <inheritdoc />
    public virtual void IncrementCheckWithoutStatusList()
    {
        ChecksWithoutStatusListCounter.Add(1);
    }

    /// <inheritdoc />
    public virtual void IncrementCertificateListed()
    {
        CertificatesListedCounter.Add(1);
    }

    /// <summary>
    ///     Releases all resources currently used by this <see cref="DefaultAndroidKeyAttestationStatusCounters" /> instance.
    /// </summary>
    /// <param name="disposing"><see langword="true" /> if this method is being invoked by the <see cref="Dispose()" /> method, otherwise <see langword="false" />.</param>
    protected virtual void Dispose(bool disposing)
    {
        if (disposing)
        {
            Meter.Dispose();
        }
    }
}
