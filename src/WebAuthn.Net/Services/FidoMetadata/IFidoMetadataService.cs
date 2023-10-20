using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Models.Abstractions;

namespace WebAuthn.Net.Services.FidoMetadata;

public interface IFidoMetadataService<TContext>
    where TContext : class, IWebAuthnContext
{
    Task<bool> FindAsync(
        TContext context,
        CancellationToken cancellationToken);
}
