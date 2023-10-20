using System.Threading;
using System.Threading.Tasks;

namespace WebAuthn.Net.Services.FidoMetadata;

public interface IFidoMetadataHttpClient
{
    Task<string> DownloadMetadataAsync(CancellationToken cancellationToken);
}
