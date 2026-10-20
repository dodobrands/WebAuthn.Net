using System;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using WebAuthn.Net.Services.FidoMetadata;
using WebAuthn.Net.Services.Metrics.Implementation.Constants;

namespace WebAuthn.Net.Services.Metrics.Implementation;

/// <summary>
///     Default implementation of <see cref="IFidoMetadataCounters" />.
/// </summary>
public class DefaultFidoMetadataCounters : IFidoMetadataCounters, IDisposable
{
    /// <summary>
    ///     Constructs <see cref="DefaultFidoMetadataCounters" />.
    /// </summary>
    public DefaultFidoMetadataCounters()
    {
        Meter = new(Meters.FidoMetadataMeterName);
        DecodeStartCounter = Meter.CreateCounter<long>(
            "webauthn.mds.decode.start",
            null,
            "The number of calls to the method responsible for decoding the FIDO Metadata Service blob (IFidoMetadataDecoder.Decode)");
        DecodeEndCounter = Meter.CreateCounter<long>(
            "webauthn.mds.decode.end",
            null,
            "The number of completions of the method responsible for decoding the FIDO Metadata Service blob (IFidoMetadataDecoder.Decode)");
        EntriesSkippedCounter = Meter.CreateCounter<long>(
            "webauthn.mds.decode.entries.skipped",
            null,
            "The number of entries of the FIDO Metadata Service blob that were skipped during decoding because they are malformed");
        StatusReportsIgnoredCounter = Meter.CreateCounter<long>(
            "webauthn.mds.decode.status_reports.ignored",
            null,
            "The number of status reports of the FIDO Metadata Service blob that were ignored during decoding because they contain a status unknown to the library");
        ValuesIgnoredCounter = Meter.CreateCounter<long>(
            "webauthn.mds.decode.values.ignored",
            null,
            "The number of values of the FIDO Metadata Service blob entries that were ignored during decoding because they are invalid, but not essential for the entry");
        BlobsRejectedCounter = Meter.CreateCounter<long>(
            "webauthn.mds.ingest.blobs.rejected",
            null,
            "The number of FIDO Metadata Service blobs that were rejected during ingestion, for example, because they would roll back the metadata in use to an older blob");
    }

    /// <summary>
    ///     <see cref="Meter" /> responsible for creating and tracking Instruments of the FIDO Metadata Service.
    /// </summary>
    protected Meter Meter { get; }

    /// <summary>
    ///     Counter for calls to the method responsible for decoding the FIDO Metadata Service blob <see cref="IFidoMetadataDecoder" />.<see cref="IFidoMetadataDecoder.Decode" />.
    /// </summary>
    protected Counter<long> DecodeStartCounter { get; }

    /// <summary>
    ///     The completion counter of the method responsible for decoding the FIDO Metadata Service blob <see cref="IFidoMetadataDecoder" />.<see cref="IFidoMetadataDecoder.Decode" />.
    /// </summary>
    protected Counter<long> DecodeEndCounter { get; }

    /// <summary>
    ///     Counter for the entries of the FIDO Metadata Service blob that were skipped during decoding.
    /// </summary>
    protected Counter<long> EntriesSkippedCounter { get; }

    /// <summary>
    ///     Counter for the status reports of the FIDO Metadata Service blob that were ignored during decoding.
    /// </summary>
    protected Counter<long> StatusReportsIgnoredCounter { get; }

    /// <summary>
    ///     Counter for the values of the FIDO Metadata Service blob entries that were ignored during decoding.
    /// </summary>
    protected Counter<long> ValuesIgnoredCounter { get; }

    /// <summary>
    ///     Counter for the FIDO Metadata Service blobs that were rejected during ingestion.
    /// </summary>
    protected Counter<long> BlobsRejectedCounter { get; }

    /// <inheritdoc />
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <inheritdoc />
    public virtual void IncrementDecodeStart()
    {
        DecodeStartCounter.Add(1);
    }

    /// <inheritdoc />
    public virtual void IncrementDecodeEnd(bool successful)
    {
        var status = successful
            ? TagValues.StatusSuccess
            : TagValues.StatusFail;
        DecodeEndCounter.Add(
            1L,
            new TagList
            {
                new(Tags.Status, status)
            });
    }

    /// <inheritdoc />
    public virtual void IncrementEntrySkipped(string member)
    {
        EntriesSkippedCounter.Add(
            1L,
            new TagList
            {
                new(Tags.Reason, member)
            });
    }

    /// <inheritdoc />
    public virtual void IncrementEntrySkippedDueToException()
    {
        EntriesSkippedCounter.Add(
            1L,
            new TagList
            {
                new(Tags.Reason, TagValues.ReasonException)
            });
    }

    /// <inheritdoc />
    public virtual void IncrementStatusReportIgnored(string status)
    {
        StatusReportsIgnoredCounter.Add(
            1L,
            new TagList
            {
                new(Tags.AuthenticatorStatus, status)
            });
    }

    /// <inheritdoc />
    public virtual void IncrementValueIgnored(string member)
    {
        ValuesIgnoredCounter.Add(
            1L,
            new TagList
            {
                new(Tags.Member, member)
            });
    }

    /// <inheritdoc />
    public virtual void IncrementBlobRejectedDueToRollback()
    {
        BlobsRejectedCounter.Add(
            1L,
            new TagList
            {
                new(Tags.Reason, TagValues.ReasonRollback)
            });
    }

    /// <summary>
    ///     Releases all resources currently used by this <see cref="DefaultFidoMetadataCounters" /> instance.
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
