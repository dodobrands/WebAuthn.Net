using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using WebAuthn.Net.Services.Context;
using WebAuthn.Net.Storage.InMemory.Models;

namespace WebAuthn.Net.Storage.InMemory.Services.ContextFactory;

public class DefaultInMemoryContextFactory : IWebAuthnContextFactory<DefaultInMemoryContext>
{
    public virtual Task<DefaultInMemoryContext> CreateAsync(HttpContext httpContext, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var context = new DefaultInMemoryContext(httpContext);
        return Task.FromResult(context);
    }
}
