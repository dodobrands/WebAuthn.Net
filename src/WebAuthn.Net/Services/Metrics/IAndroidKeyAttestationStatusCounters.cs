using WebAuthn.Net.Services.AndroidKeyAttestationStatus;

namespace WebAuthn.Net.Services.Metrics;

/// <summary>
///     Counters for the metrics of the <a href="https://developer.android.com/privacy-and-security/security-key-attestation#certificate_status">certificate revocation status list</a> of the Android attestation keys.
/// </summary>
public interface IAndroidKeyAttestationStatusCounters
{
    /// <summary>
    ///     Increments the counter of the status lists that could not be downloaded, or were rejected after the download because they are malformed.
    /// </summary>
    /// <param name="reason">The reason, one of a bounded set of values defined by the provider of the status list (for example, <c>request_failed</c>).</param>
    void IncrementDownloadFailure(string reason);

    /// <summary>
    ///     Increments the counter of the status lists embedded in the application that could not be loaded, or were rejected because they are malformed.
    /// </summary>
    /// <param name="reason">The reason, one of a bounded set of values defined by the provider of the status list (for example, <c>resource_not_found</c>).</param>
    void IncrementEmbeddedFailure(string reason);

    /// <summary>
    ///     Increments the counter of the attempts to load and store the status list that ended with an unexpected exception
    ///     (for example, an exception of a resilience policy of the HttpClient or a timeout of a persistent storage) instead of a failed result.
    /// </summary>
    /// <param name="source">The source of the status list, one of a bounded set of values defined by the background ingestion (<c>embedded</c> or <c>download</c>).</param>
    void IncrementIngestException(string source);

    /// <summary>
    ///     Increments the counter of the anomalies found by <see cref="IAndroidKeyAttestationStatusDecoder" /> in the entries of the status list.
    /// </summary>
    /// <param name="anomaly">The anomaly, one of a bounded set of values defined by the decoder (for example, <c>status.unknown</c>).</param>
    /// <param name="tolerated">Flag indicating whether the entry was kept despite the anomaly (<see langword="true" />) or skipped (<see langword="false" />).</param>
    void IncrementDecodeAnomaly(string anomaly, bool tolerated);

    /// <summary>
    ///     Increments the counter of the attestation statements whose certificate chain ends at a root certificate of the key attestation of Google that were rejected because no status list is available
    ///     (for example, before the first successful download).
    /// </summary>
    void IncrementCheckWithoutStatusList();

    /// <summary>
    ///     Increments the counter of the attestation statements whose certificate chain ends at a root certificate of the key attestation of Google that were rejected because a certificate of the chain is in the status list.
    /// </summary>
    void IncrementCertificateListed();
}
