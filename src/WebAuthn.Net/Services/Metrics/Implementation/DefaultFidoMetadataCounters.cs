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
        DownloadStartCounter = Meter.CreateCounter<long>(
            "webauthn.mds.download.start",
            null,
            "The number of calls to the method responsible for downloading the FIDO Metadata Service blob and verifying its signature (IFidoMetadataProvider.DownloadMetadataAsync)");
        DownloadEndCounter = Meter.CreateCounter<long>(
            "webauthn.mds.download.end",
            null,
            "The number of completions of the method responsible for downloading the FIDO Metadata Service blob and verifying its signature (IFidoMetadataProvider.DownloadMetadataAsync)");
        DownloadFailuresCounter = Meter.CreateCounter<long>(
            "webauthn.mds.download.failures",
            null,
            "The number of FIDO Metadata Service blobs that could not be downloaded, or were rejected after the download because they are malformed or their signature could not be verified");
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
            "The number of values of the FIDO Metadata Service blob (of its payload or of its entries) that were ignored during decoding because they are invalid, but not essential");
        BlobsRejectedCounter = Meter.CreateCounter<long>(
            "webauthn.mds.ingest.blobs.rejected",
            null,
            "The number of FIDO Metadata Service blobs that were rejected during ingestion because they would roll back the metadata in use to a blob with a lower serial number");
        LookupsWithoutMetadataCounter = Meter.CreateCounter<long>(
            "webauthn.mds.search.no_metadata",
            null,
            "The number of metadata lookups that can't succeed because no FIDO Metadata Service blob is available in the storage (for example, before the first successful ingestion)");
    }

    /// <summary>
    ///     <see cref="Meter" /> responsible for creating and tracking Instruments of the FIDO Metadata Service.
    /// </summary>
    protected Meter Meter { get; }

    /// <summary>
    ///     Counter for calls to the method responsible for downloading the FIDO Metadata Service blob and verifying its signature <see cref="IFidoMetadataProvider" />.<see cref="IFidoMetadataProvider.DownloadMetadataAsync" />.
    /// </summary>
    protected Counter<long> DownloadStartCounter { get; }

    /// <summary>
    ///     The completion counter of the method responsible for downloading the FIDO Metadata Service blob and verifying its signature <see cref="IFidoMetadataProvider" />.<see cref="IFidoMetadataProvider.DownloadMetadataAsync" />.
    /// </summary>
    protected Counter<long> DownloadEndCounter { get; }

    /// <summary>
    ///     Counter for the FIDO Metadata Service blobs that could not be downloaded, or were rejected after the download.
    /// </summary>
    protected Counter<long> DownloadFailuresCounter { get; }

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
    ///     Counter for the values of the FIDO Metadata Service blob that were ignored during decoding.
    /// </summary>
    protected Counter<long> ValuesIgnoredCounter { get; }

    /// <summary>
    ///     Counter for the FIDO Metadata Service blobs that were rejected during ingestion.
    /// </summary>
    protected Counter<long> BlobsRejectedCounter { get; }

    /// <summary>
    ///     Counter for the metadata lookups that can't succeed because no FIDO Metadata Service blob is available in the storage.
    /// </summary>
    protected Counter<long> LookupsWithoutMetadataCounter { get; }

    /// <inheritdoc />
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <inheritdoc />
    public virtual void IncrementDownloadStart()
    {
        DownloadStartCounter.Add(1);
    }

    /// <inheritdoc />
    public virtual void IncrementDownloadEnd(bool successful)
    {
        var status = successful
            ? TagValues.StatusSuccess
            : TagValues.StatusFail;
        DownloadEndCounter.Add(
            1L,
            new TagList
            {
                new(Tags.Status, status)
            });
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

    /// <inheritdoc />
    public virtual void IncrementLookupWithoutMetadata()
    {
        LookupsWithoutMetadataCounter.Add(1);
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
