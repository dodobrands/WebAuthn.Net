using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder;
using WebAuthn.Net.Services.Metrics;
using WebAuthn.Net.Services.Metrics.Implementation;
using WebAuthn.Net.Storage.FidoMetadata;

namespace WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataIngestService;

/// <summary>
///     Default implementation of <see cref="IFidoMetadataIngestService" />.
/// </summary>
/// <remarks>
///     <para>
///         The service protects the metadata from a rollback. The serial numbers of the blobs (the <c>no</c> member)
///         <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#sctn-mds-payload-blob">MUST be consecutive and strictly monotonic</a>,
///         so a blob whose serial number is lower than the serial number of the blob in use is an older blob: although it may be correctly signed,
///         it would silently restore the trust in the authenticators that have been revoked since then. Such a blob is rejected, logged and counted.
///         A blob with the same serial number is accepted again, because the FIDO Metadata Service publishes the same blob until the next update.
///     </para>
///     <para>
///         The serial number of the blob in use is the greater of the value reported by the storage (<see cref="IFidoMetadataIngestStorage.GetCurrentBlobNoAsync" />)
///         and the serial number of the last blob accepted by this instance (<see cref="LastAcceptedNo" />), so the protection works within the lifetime of the application
///         with any storage and also across its restarts with a storage that tracks the serial number of the stored blob.
///     </para>
///     <para>
///         The blob embedded in the application (<see cref="UpsertEmbeddedAsync" />) is upserted only if it is newer than the blob in use: it is a fallback for the start without the FIDO Metadata Service,
///         so an embedded blob that is older than the metadata in use is expected and is not reported as a rollback.
///     </para>
/// </remarks>
public class DefaultFidoMetadataIngestService : IFidoMetadataIngestService
{
    /// <summary>
    ///     Constructs <see cref="DefaultFidoMetadataIngestService" /> that doesn't report the rejected blobs to the metrics and the log.
    /// </summary>
    /// <remarks>
    ///     The protection from a rollback works, but the rejected blobs are neither counted nor logged.
    ///     Use <see cref="DefaultFidoMetadataIngestService(IFidoMetadataIngestStorage, IFidoMetadataCounters, ILogger{DefaultFidoMetadataIngestService})" /> to report them.
    /// </remarks>
    /// <param name="metadataIngestStorage">Storage designed for the ingestion of metadata obtained from the FIDO Metadata Service.</param>
    /// <exception cref="ArgumentNullException">Any of the parameters is <see langword="null" /></exception>
    public DefaultFidoMetadataIngestService(IFidoMetadataIngestStorage metadataIngestStorage)
        : this(metadataIngestStorage, NullFidoMetadataCounters.Instance, NullLogger<DefaultFidoMetadataIngestService>.Instance)
    {
    }

    /// <summary>
    ///     Constructs <see cref="DefaultFidoMetadataIngestService" />
    /// </summary>
    /// <param name="metadataIngestStorage">Storage designed for the ingestion of metadata obtained from the FIDO Metadata Service.</param>
    /// <param name="counters">Counters for FIDO Metadata Service metrics.</param>
    /// <param name="logger">Logger.</param>
    /// <exception cref="ArgumentNullException">Any of the parameters is <see langword="null" /></exception>
    public DefaultFidoMetadataIngestService(
        IFidoMetadataIngestStorage metadataIngestStorage,
        IFidoMetadataCounters counters,
        ILogger<DefaultFidoMetadataIngestService> logger)
    {
        ArgumentNullException.ThrowIfNull(metadataIngestStorage);
        ArgumentNullException.ThrowIfNull(counters);
        ArgumentNullException.ThrowIfNull(logger);
        MetadataIngestStorage = metadataIngestStorage;
        Counters = counters;
        Logger = logger;
    }

    /// <summary>
    ///     Storage designed for the ingestion of metadata obtained from the FIDO Metadata Service.
    /// </summary>
    protected IFidoMetadataIngestStorage MetadataIngestStorage { get; }

    /// <summary>
    ///     Counters for FIDO Metadata Service metrics.
    /// </summary>
    protected IFidoMetadataCounters Counters { get; }

    /// <summary>
    ///     Logger.
    /// </summary>
    protected ILogger<DefaultFidoMetadataIngestService> Logger { get; }

    /// <summary>
    ///     The serial number (the <c>no</c> member) of the last blob accepted by this instance, or <see langword="null" /> if this instance hasn't accepted a blob yet.
    /// </summary>
    /// <remarks>
    ///     Protects the metadata from a rollback within the lifetime of this instance even when the storage doesn't track the serial number of the stored blob.
    ///     The value is not synchronized: the blobs are expected to be upserted sequentially, as the background ingestion does.
    /// </remarks>
    protected long? LastAcceptedNo { get; set; }

    /// <inheritdoc />
    /// <remarks>
    ///     The blob is rejected (not upserted) if it would roll back the metadata in use to an older blob, see <see cref="CanReplaceCurrentBlob" />.
    ///     The rejection is logged at the <see cref="LogLevel.Warning" /> level and counted.
    /// </remarks>
    public virtual async Task UpsertAsync(
        MetadataBlobPayload metadataBlob,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(metadataBlob);
        cancellationToken.ThrowIfCancellationRequested();
        var currentNo = await GetBlobNoInUseAsync(cancellationToken);
        if (currentNo.HasValue && !CanReplaceCurrentBlob(currentNo.Value, metadataBlob))
        {
            Logger.WarnBlobRejectedDueToRollback(metadataBlob.No, currentNo.Value);
            Counters.IncrementBlobRejectedDueToRollback();
            return;
        }

        await MetadataIngestStorage.UpsertAsync(metadataBlob, cancellationToken);
        LastAcceptedNo = metadataBlob.No;
        Logger.InfoBlobIngested(metadataBlob.No, metadataBlob.Entries.Length);
    }

    /// <inheritdoc />
    /// <remarks>
    ///     The embedded blob is upserted only if it is newer than the blob in use (see <see cref="GetBlobNoInUseAsync" />) or if there is no blob in use yet.
    ///     Otherwise the metadata in use is kept: unlike an older blob served by the FIDO Metadata Service, an older embedded blob is expected and is not a rollback,
    ///     so it is logged at the <see cref="LogLevel.Information" /> level and is not counted as a rejected blob.
    /// </remarks>
    public virtual async Task UpsertEmbeddedAsync(
        MetadataBlobPayload metadataBlob,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(metadataBlob);
        cancellationToken.ThrowIfCancellationRequested();
        var currentNo = await GetBlobNoInUseAsync(cancellationToken);
        if (currentNo.HasValue && metadataBlob.No <= currentNo.Value)
        {
            Logger.InfoEmbeddedBlobNotNewer(metadataBlob.No, currentNo.Value);
            return;
        }

        await MetadataIngestStorage.UpsertAsync(metadataBlob, cancellationToken);
        LastAcceptedNo = metadataBlob.No;
        Logger.InfoEmbeddedBlobIngested(metadataBlob.No, metadataBlob.Entries.Length);
    }

    /// <summary>
    ///     Returns the serial number (the <c>no</c> member) of the blob in use, which a new blob must not roll back.
    /// </summary>
    /// <remarks>
    ///     The default implementation returns the greater of the serial number reported by the storage (<see cref="IFidoMetadataIngestStorage.GetCurrentBlobNoAsync" />)
    ///     and <see cref="LastAcceptedNo" />, so that the protection from a rollback works both with a storage that doesn't track the serial number of the stored blob
    ///     (within the lifetime of this instance) and across the restarts of the application with a storage that does.
    /// </remarks>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>The serial number of the blob in use, or <see langword="null" /> if no blob is in use yet (any blob is accepted).</returns>
    protected virtual async Task<long?> GetBlobNoInUseAsync(CancellationToken cancellationToken)
    {
        var storedNo = await MetadataIngestStorage.GetCurrentBlobNoAsync(cancellationToken);
        var lastAcceptedNo = LastAcceptedNo;
        if (storedNo is null)
        {
            return lastAcceptedNo;
        }

        if (lastAcceptedNo is null)
        {
            return storedNo;
        }

        return Math.Max(storedNo.Value, lastAcceptedNo.Value);
    }

    /// <summary>
    ///     Decides whether the blob may replace the blob in use.
    /// </summary>
    /// <remarks>
    ///     The default implementation accepts the blob only if its serial number (the <c>no</c> member) is not lower than the serial number of the blob in use:
    ///     an equal serial number means that the same blob was downloaded again, a greater one - an update. Override this method to apply a different policy,
    ///     for example, to require a strictly greater serial number.
    /// </remarks>
    /// <param name="currentNo">The serial number of the blob in use.</param>
    /// <param name="metadataBlob">The blob that is going to be upserted.</param>
    /// <returns><see langword="true" /> if the blob may replace the blob in use, otherwise - <see langword="false" /> (the blob is rejected).</returns>
    protected virtual bool CanReplaceCurrentBlob(long currentNo, MetadataBlobPayload metadataBlob)
    {
        ArgumentNullException.ThrowIfNull(metadataBlob);
        return metadataBlob.No >= currentNo;
    }
}

/// <summary>
///     Extension methods for logging the ingestion of the FIDO Metadata Service blob.
/// </summary>
public static partial class DefaultFidoMetadataIngestServiceLoggingExtensions
{
    /// <summary>
    ///     The FIDO Metadata Service blob (no: {No}) was rejected because it would roll back the metadata in use (no: {CurrentNo}) to an older blob
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="no">The serial number of the rejected blob.</param>
    /// <param name="currentNo">The serial number of the blob in use.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The FIDO Metadata Service blob (no: {No}) was rejected because it would roll back the metadata in use (no: {CurrentNo}) to an older blob")]
    public static partial void WarnBlobRejectedDueToRollback(this ILogger logger, long no, long currentNo);

    /// <summary>
    ///     The FIDO Metadata Service blob (no: {No}) with {Entries} entries was ingested
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="no">The serial number of the ingested blob.</param>
    /// <param name="entries">The number of entries in the ingested blob.</param>
    [LoggerMessage(
        Level = LogLevel.Information,
        Message = "The FIDO Metadata Service blob (no: {No}) with {Entries} entries was ingested")]
    public static partial void InfoBlobIngested(this ILogger logger, long no, int entries);

    /// <summary>
    ///     The FIDO Metadata Service blob (no: {No}) with {Entries} entries embedded in the application was ingested
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="no">The serial number of the ingested blob.</param>
    /// <param name="entries">The number of entries in the ingested blob.</param>
    [LoggerMessage(
        Level = LogLevel.Information,
        Message = "The FIDO Metadata Service blob (no: {No}) with {Entries} entries embedded in the application was ingested")]
    public static partial void InfoEmbeddedBlobIngested(this ILogger logger, long no, int entries);

    /// <summary>
    ///     The FIDO Metadata Service blob (no: {No}) embedded in the application was not ingested because the metadata in use (no: {CurrentNo}) is not older
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="no">The serial number of the embedded blob.</param>
    /// <param name="currentNo">The serial number of the blob in use.</param>
    [LoggerMessage(
        Level = LogLevel.Information,
        Message = "The FIDO Metadata Service blob (no: {No}) embedded in the application was not ingested because the metadata in use (no: {CurrentNo}) is not older")]
    public static partial void InfoEmbeddedBlobNotNewer(this ILogger logger, long no, long currentNo);
}
