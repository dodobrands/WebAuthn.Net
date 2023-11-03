using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder;
using WebAuthn.Net.Storage.FidoMetadata;

namespace WebAuthn.Net.Mysql.Storage;

public class MysqlFidoMetadataStorage : IFidoMetadataStorage
{
    public async Task StoreAsync(MetadataBlobPayload blob, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public async Task<MetadataBlobPayloadEntry?> FindByAaguidAsync(Guid aaguid, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public async Task<MetadataBlobPayloadEntry?> FindBySubjectKeyIdentifierAsync(byte[] subjectKeyIdentifier, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }
}
