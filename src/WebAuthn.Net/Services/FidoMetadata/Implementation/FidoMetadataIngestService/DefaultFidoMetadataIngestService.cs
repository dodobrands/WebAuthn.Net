using System;
using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder;
using WebAuthn.Net.Storage.FidoMetadata;

namespace WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataIngestService;

public class DefaultFidoMetadataIngestService : IFidoMetadataIngestService
{
    public DefaultFidoMetadataIngestService(IFidoMetadataIngestStorage metadataIngestStorage)
    {
        ArgumentNullException.ThrowIfNull(metadataIngestStorage);
        MetadataIngestStorage = metadataIngestStorage;
    }

    protected IFidoMetadataIngestStorage MetadataIngestStorage { get; }

    public virtual async Task UpsertAsync(
        MetadataBlobPayload metadataBlob,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await MetadataIngestStorage.UpsertAsync(metadataBlob, cancellationToken);
    }
}
