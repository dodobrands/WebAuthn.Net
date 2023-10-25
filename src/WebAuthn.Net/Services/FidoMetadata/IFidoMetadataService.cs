using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataService;

namespace WebAuthn.Net.Services.FidoMetadata;

public interface IFidoMetadataService<TContext>
    where TContext : class, IWebAuthnContext
{
    Task<FidoMetadataSearchResult?> FindMetadataAsync(
        TContext context,
        byte[] aaguidBytes,
        CancellationToken cancellationToken);
}
