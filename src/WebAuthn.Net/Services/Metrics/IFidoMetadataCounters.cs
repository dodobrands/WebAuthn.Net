using WebAuthn.Net.Services.FidoMetadata;

namespace WebAuthn.Net.Services.Metrics;

/// <summary>
///     Counters for FIDO Metadata Service metrics.
/// </summary>
public interface IFidoMetadataCounters
{
    /// <summary>
    ///     Increments the counter of <see cref="IFidoMetadataProvider" />.<see cref="IFidoMetadataProvider.DownloadMetadataAsync" /> calls.
    /// </summary>
    void IncrementDownloadStart();

    /// <summary>
    ///     Increments the counter of <see cref="IFidoMetadataProvider" />.<see cref="IFidoMetadataProvider.DownloadMetadataAsync" /> completions.
    /// </summary>
    /// <param name="successful">Flag indicating whether the completion was successful: the blob was downloaded and its signature was verified.</param>
    void IncrementDownloadEnd(bool successful);

    /// <summary>
    ///     Increments the counter of the FIDO Metadata Service blobs that could not be downloaded, or were rejected after the download because they are malformed or their signature could not be verified.
    /// </summary>
    /// <param name="reason">The reason, one of a bounded set of values defined by the provider of the metadata (for example, <c>chain_invalid</c>).</param>
    void IncrementDownloadFailure(string reason);

    /// <summary>
    ///     Increments the counter of <see cref="IFidoMetadataDecoder" />.<see cref="IFidoMetadataDecoder.Decode" /> calls.
    /// </summary>
    void IncrementDecodeStart();

    /// <summary>
    ///     Increments the counter of <see cref="IFidoMetadataDecoder" />.<see cref="IFidoMetadataDecoder.Decode" /> completions.
    /// </summary>
    /// <param name="successful">Flag indicating whether the completion was successful.</param>
    void IncrementDecodeEnd(bool successful);

    /// <summary>
    ///     Increments the counter of the entries of the FIDO Metadata Service blob that were skipped during decoding because a member of the entry is missing or invalid.
    /// </summary>
    /// <param name="member">The path of the member of the entry that is missing or invalid, without array indices (for example, <c>statusReports[].effectiveDate</c>).</param>
    void IncrementEntrySkipped(string member);

    /// <summary>
    ///     Increments the counter of the entries of the FIDO Metadata Service blob that were skipped during decoding because an error occurred during the decoding of the entry.
    /// </summary>
    void IncrementEntrySkippedDueToException();

    /// <summary>
    ///     Increments the counter of the status reports of the FIDO Metadata Service blob that were ignored during decoding because their <c>status</c> member contains a value unknown to the library.
    /// </summary>
    /// <param name="status">The unknown value of the <c>status</c> member of the status report.</param>
    void IncrementStatusReportIgnored(string status);

    /// <summary>
    ///     Increments the counter of the values of the FIDO Metadata Service blob that were ignored during decoding because they are invalid, but not essential
    ///     (for example, a <c>nextUpdate</c> that is not an ISO-8601 date, or a vendorCommandId of an entry outside the uint64 range).
    /// </summary>
    /// <param name="member">
    ///     The path of the member whose value was ignored, without array indices: the name of a member of the blob payload (<c>nextUpdate</c>),
    ///     or the path of a member of an entry relative to the entry (for example, <c>metadataStatement.authenticatorGetInfo.vendorPrototypeConfigCommands[]</c>).
    /// </param>
    void IncrementValueIgnored(string member);

    /// <summary>
    ///     Increments the counter of the FIDO Metadata Service blobs that were rejected during ingestion because they would roll back the metadata in use to a blob with a lower serial number (the <c>no</c> member).
    /// </summary>
    void IncrementBlobRejectedDueToRollback();

    /// <summary>
    ///     Increments the counter of the metadata lookups (<see cref="IFidoMetadataSearchService{TContext}" />) that can't succeed because no FIDO Metadata Service blob is available in the storage
    ///     (for example, before the first successful ingestion).
    /// </summary>
    void IncrementLookupWithoutMetadata();
}
