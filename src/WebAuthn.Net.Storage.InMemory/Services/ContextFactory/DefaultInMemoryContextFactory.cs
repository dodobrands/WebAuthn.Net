using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using WebAuthn.Net.Services.Context;
using WebAuthn.Net.Storage.InMemory.Models;

namespace WebAuthn.Net.Storage.InMemory.Services.ContextFactory;

/// <summary>
///     Default implementation of <see cref="IWebAuthnContextFactory{DefaultInMemoryContext}" /> for in-memory storage.
/// </summary>
public class DefaultInMemoryContextFactory : IWebAuthnContextFactory<DefaultInMemoryContext>
{
    /// <inheritdoc />
    public virtual Task<DefaultInMemoryContext> CreateAsync(
        HttpContext httpContext,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var context = new DefaultInMemoryContext(httpContext);
        return Task.FromResult(context);
    }
}
