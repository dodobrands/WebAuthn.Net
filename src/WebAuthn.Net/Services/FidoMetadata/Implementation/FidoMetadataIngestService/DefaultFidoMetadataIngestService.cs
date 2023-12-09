using System;
using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder;
using WebAuthn.Net.Storage.FidoMetadata;

namespace WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataIngestService;

/// <summary>
///     Default implementation of <see cref="IFidoMetadataIngestService" />.
/// </summary>
public class DefaultFidoMetadataIngestService : IFidoMetadataIngestService
{
    /// <summary>
    ///     Constructs <see cref="DefaultFidoMetadataIngestService" />
    /// </summary>
    /// <param name="metadataIngestStorage">Storage designed for the ingestion of metadata obtained from the FIDO Metadata Service.</param>
    /// <exception cref="ArgumentNullException">Any of the parameters is <see langword="null" /></exception>
    public DefaultFidoMetadataIngestService(IFidoMetadataIngestStorage metadataIngestStorage)
    {
        ArgumentNullException.ThrowIfNull(metadataIngestStorage);
        MetadataIngestStorage = metadataIngestStorage;
    }

    /// <summary>
    ///     Storage designed for the ingestion of metadata obtained from the FIDO Metadata Service.
    /// </summary>
    protected IFidoMetadataIngestStorage MetadataIngestStorage { get; }

    /// <inheritdoc />
    public virtual async Task UpsertAsync(
        MetadataBlobPayload metadataBlob,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await MetadataIngestStorage.UpsertAsync(metadataBlob, cancellationToken);
    }
}
