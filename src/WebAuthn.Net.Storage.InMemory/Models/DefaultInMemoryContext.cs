using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using WebAuthn.Net.Models.Abstractions;

namespace WebAuthn.Net.Storage.InMemory.Models;

public class DefaultInMemoryContext : IWebAuthnContext
{
    public DefaultInMemoryContext(HttpContext httpContext)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        HttpContext = httpContext;
    }

    public HttpContext HttpContext { get; }

    public virtual Task CommitAsync(CancellationToken cancellationToken)
    {
        return Task.CompletedTask;
    }

    public async ValueTask DisposeAsync()
    {
        await DisposeAsyncCore();
        GC.SuppressFinalize(this);
    }

    protected virtual ValueTask DisposeAsyncCore()
    {
        return ValueTask.CompletedTask;
    }
}
