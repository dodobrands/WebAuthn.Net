using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataProvider.Protocol.Json;

namespace WebAuthn.Net.Services.FidoMetadata;

public interface IFidoMetadataProvider
{
    Task<Result<MetadataBLOBPayloadJSON>> DownloadMetadataAsync(CancellationToken cancellationToken);
}
