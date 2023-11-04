using System;
using System.Threading;
using System.Threading.Tasks;

namespace WebAuthn.Net.Models.Abstractions;

/// <summary>
///     The context in which the WebAuthn operation is being processed.
/// </summary>
public interface IWebAuthnContext : IAsyncDisposable
{
    /// <summary>
    ///     Save the changes made in this context.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    Task CommitAsync(CancellationToken cancellationToken);
}
