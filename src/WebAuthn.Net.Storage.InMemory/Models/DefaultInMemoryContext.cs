using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using WebAuthn.Net.Models.Abstractions;

namespace WebAuthn.Net.Storage.InMemory.Models;

/// <summary>
///     Default implementation of <see cref="IWebAuthnContext" /> for in-memory storage
/// </summary>
public class DefaultInMemoryContext : IWebAuthnContext
{
    /// <summary>
    ///     Constructs <see cref="DefaultInMemoryContext" />.
    /// </summary>
    /// <param name="httpContext">The context of the HTTP request in which the WebAuthn operation is being processed.</param>
    /// <exception cref="ArgumentNullException">Any of the parameters is <see langword="null" /></exception>
    public DefaultInMemoryContext(HttpContext httpContext)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        HttpContext = httpContext;
    }

    /// <inheritdoc />
    public HttpContext HttpContext { get; }

    /// <inheritdoc />
    public virtual Task CommitAsync(CancellationToken cancellationToken)
    {
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        await DisposeAsyncCore();
        GC.SuppressFinalize(this);
    }

    /// <summary>
    ///     Performs asynchronous release of unmanaged resources. May be overridden by descendants.
    /// </summary>
    protected virtual ValueTask DisposeAsyncCore()
    {
        return ValueTask.CompletedTask;
    }
}
