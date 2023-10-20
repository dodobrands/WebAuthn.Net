using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataProvider.Protocol.Json;

namespace WebAuthn.Net.Services.FidoMetadata;

public interface IFidoMetadataProvider
{
    Task<MetadataBLOBPayloadJSON> DownloadMetadataAsync(CancellationToken cancellationToken);
}
