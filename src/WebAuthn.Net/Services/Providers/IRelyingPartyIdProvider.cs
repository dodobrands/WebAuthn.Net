using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace WebAuthn.Net.Services.Providers;

public interface IRelyingPartyIdProvider
{
    Task<string> GetAsync(HttpContext httpContext, CancellationToken cancellationToken);
}
