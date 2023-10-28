using System;
using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder;

namespace WebAuthn.Net.Storage.FidoMetadata;

public interface IFidoMetadataStorage
{
    Task StoreAsync(MetadataBlobPayload blob, CancellationToken cancellationToken);
    Task<MetadataBlobPayloadEntry?> FindByAaguidAsync(Guid aaguid, CancellationToken cancellationToken);
    Task<MetadataBlobPayloadEntry?> FindBySubjectKeyIdentifierAsync(byte[] subjectKeyIdentifier, CancellationToken cancellationToken);
}
