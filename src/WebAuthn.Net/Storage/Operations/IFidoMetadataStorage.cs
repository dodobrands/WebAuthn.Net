using System;
using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder;

namespace WebAuthn.Net.Storage.Operations;

public interface IFidoMetadataStorage
{
    Task StoreAsync(MetadataBlobPayload blob, CancellationToken cancellationToken);

    Task<MetadataBlobPayloadEntry?> FindAsync(Guid aaguid, CancellationToken cancellationToken);
}
