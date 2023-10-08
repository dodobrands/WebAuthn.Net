using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Models.Abstractions;

namespace WebAuthn.Net.Services.Providers;

public interface IRelyingPartyOriginProvider<TContext>
    where TContext : class, IWebAuthnContext
{
    Task<string> GetAsync(TContext context, CancellationToken cancellationToken);
}
