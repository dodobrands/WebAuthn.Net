using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace WebAuthn.Net.Services.Providers;

/// <summary>
///     Provider of the rpId value based on the <see cref="HttpContext" />.
/// </summary>
public interface IRelyingPartyIdProvider
{
    /// <summary>
    ///     Asynchronously computes and returns the rpId value for the current request based on data in <see cref="HttpContext" />.
    /// </summary>
    /// <param name="httpContext">The context of the HTTP request in which the WebAuthn operation is being processed.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>rpId for the current request</returns>
    Task<string> GetAsync(HttpContext httpContext, CancellationToken cancellationToken);
}
