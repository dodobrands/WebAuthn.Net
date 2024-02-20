using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace WebAuthn.Net.Services.Providers.Implementation;

/// <summary>
///     Default implementation of <see cref="IRelyingPartyIdProvider" />.
/// </summary>
public class DefaultRelyingPartyIdProvider : IRelyingPartyIdProvider
{
    /// <inheritdoc />
    public virtual Task<string> GetAsync(HttpContext httpContext, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        cancellationToken.ThrowIfCancellationRequested();
        var baseAddress = httpContext.Request.Scheme + Uri.SchemeDelimiter + httpContext.Request.Host + httpContext.Request.PathBase;
        var baseUri = new Uri(baseAddress, UriKind.Absolute);
        if (baseUri.Scheme != Uri.UriSchemeHttp && baseUri.Scheme != Uri.UriSchemeHttps)
        {
            throw new InvalidOperationException($"Invalid request scheme. Only '{Uri.UriSchemeHttp}' and '{Uri.UriSchemeHttps}' are allowed.");
        }

        var effectiveDomain = baseUri.Host;
        return Task.FromResult(effectiveDomain);
    }
}
