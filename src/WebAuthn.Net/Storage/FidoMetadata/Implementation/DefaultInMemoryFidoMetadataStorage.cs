using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Services.FidoMetadata;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder;
using WebAuthn.Net.Storage.FidoMetadata.Models.Enums;

namespace WebAuthn.Net.Storage.FidoMetadata.Implementation;

/// <summary>
///     The default in-memory implementation of storage for metadata obtained from the FIDO Metadata Service.
/// </summary>
/// <remarks>
///     Until the first blob is upserted, the storage contains no metadata: the search methods report <see cref="FidoMetadataSearchStorageError.MetadataNotAvailable" />
///     and <see cref="GetCurrentBlobNoAsync" /> returns <see langword="null" />.
/// </remarks>
/// <typeparam name="TContext">The type of context in which the WebAuthn operation will be performed.</typeparam>
public class DefaultInMemoryFidoMetadataStorage<TContext> :
    IFidoMetadataSearchStorage<TContext>,
    IFidoMetadataIngestStorage
    where TContext : class, IWebAuthnContext
{
    /// <summary>
    ///     The current valid blob with metadata.
    /// </summary>
    protected MetadataBlobPayload? Blob { get; set; }

    /// <inheritdoc />
    /// <remarks>
    ///     The blob replaces the stored one unconditionally. The protection from a rollback to a blob with a lower serial number
    ///     is performed by the ingestion service (<see cref="IFidoMetadataIngestService" />) before this method is called.
    /// </remarks>
    public virtual Task UpsertAsync(MetadataBlobPayload metadataBlob, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Blob = metadataBlob;
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public virtual Task<long?> GetCurrentBlobNoAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var currentBlob = Blob;
        return Task.FromResult(currentBlob?.No);
    }

    /// <inheritdoc />
    public virtual Task<Result<MetadataBlobPayloadEntry, FidoMetadataSearchStorageError>> FindByAaguidAsync(
        TContext context,
        Guid aaguid,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var currentBlob = Blob;
        if (currentBlob is null)
        {
            // No blob has been ingested yet, so there is nothing to search in. The absence of the metadata is reported by the search service.
            return Task.FromResult(Result<MetadataBlobPayloadEntry, FidoMetadataSearchStorageError>.Fail(FidoMetadataSearchStorageError.MetadataNotAvailable));
        }

        var entry = currentBlob.Entries.FirstOrDefault(x => x.Aaguid == aaguid);
        if (entry is null)
        {
            return Task.FromResult(Result<MetadataBlobPayloadEntry, FidoMetadataSearchStorageError>.Fail(FidoMetadataSearchStorageError.NotFound));
        }

        return Task.FromResult(Result<MetadataBlobPayloadEntry, FidoMetadataSearchStorageError>.Success(entry));
    }

    /// <inheritdoc />
    public virtual Task<Result<MetadataBlobPayloadEntry, FidoMetadataSearchStorageError>> FindBySubjectKeyIdentifierAsync(
        TContext context,
        byte[] subjectKeyIdentifier,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var currentBlob = Blob;
        if (currentBlob is null)
        {
            // No blob has been ingested yet, so there is nothing to search in. The absence of the metadata is reported by the search service.
            return Task.FromResult(Result<MetadataBlobPayloadEntry, FidoMetadataSearchStorageError>.Fail(FidoMetadataSearchStorageError.MetadataNotAvailable));
        }

        var entry = currentBlob.Entries.FirstOrDefault(x =>
            x.AttestationCertificateKeyIdentifiers is not null
            && x.AttestationCertificateKeyIdentifiers.Any(y => y.AsSpan().SequenceEqual(subjectKeyIdentifier.AsSpan())));
        if (entry is null)
        {
            return Task.FromResult(Result<MetadataBlobPayloadEntry, FidoMetadataSearchStorageError>.Fail(FidoMetadataSearchStorageError.NotFound));
        }

        return Task.FromResult(Result<MetadataBlobPayloadEntry, FidoMetadataSearchStorageError>.Success(entry));
    }
}
