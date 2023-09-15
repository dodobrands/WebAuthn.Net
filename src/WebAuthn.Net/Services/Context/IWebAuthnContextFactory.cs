using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using WebAuthn.Net.Models.Abstractions;

namespace WebAuthn.Net.Services.Context;

public interface IWebAuthnContextFactory<TContext>
    where TContext : class, IWebAuthnContext
{
    Task<TContext> CreateAsync(HttpContext httpContext, CancellationToken cancellationToken);
}
