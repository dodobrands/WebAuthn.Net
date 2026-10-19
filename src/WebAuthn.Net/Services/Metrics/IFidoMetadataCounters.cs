using WebAuthn.Net.Services.FidoMetadata;

namespace WebAuthn.Net.Services.Metrics;

/// <summary>
///     Counters for FIDO Metadata Service metrics.
/// </summary>
public interface IFidoMetadataCounters
{
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
    ///     Increments the counter of the values of the FIDO Metadata Service blob entries that were ignored during decoding because they are invalid, but not essential for the entry (for example, a vendorCommandId outside the uint64 range).
    /// </summary>
    /// <param name="member">The path of the member of the entry whose value was ignored, without array indices (for example, <c>metadataStatement.authenticatorGetInfo.vendorPrototypeConfigCommands[]</c>).</param>
    void IncrementValueIgnored(string member);
}
