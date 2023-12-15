using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using WebAuthn.Net.Models.Abstractions;

namespace WebAuthn.Net.Services.Context;

/// <summary>
///     Factory for creating a WebAuthn operation context.
/// </summary>
/// <typeparam name="TContext">The type of context for a WebAuthn operation.</typeparam>
public interface IWebAuthnContextFactory<TContext>
    where TContext : class, IWebAuthnContext
{
    /// <summary>
    ///     Creates the context for a WebAuthn operation.
    /// </summary>
    /// <param name="httpContext">The context of the HTTP request in which the WebAuthn operation is being processed.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>The context of a WebAuthn operation.</returns>
    Task<TContext> CreateAsync(
        HttpContext httpContext,
        CancellationToken cancellationToken);
}
