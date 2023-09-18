using System;
using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Models.Abstractions;

namespace WebAuthn.Net.Services.RelyingPartyOrigin.Implementation;

public class DefaultRelyingPartyOriginProvider<TContext> : IRelyingPartyOriginProvider<TContext>
    where TContext : class, IWebAuthnContext
{
    public Task<string> GetAsync(TContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();
        var baseAddress = context.HttpContext.Request.Scheme + Uri.SchemeDelimiter + context.HttpContext.Request.Host + context.HttpContext.Request.PathBase;
        var baseUri = new Uri(baseAddress, UriKind.Absolute);
        var result = baseAddress;
        if (baseUri.HostNameType != UriHostNameType.Unknown)
        {
            if (baseUri.IsDefaultPort)
            {
                result = $"{baseUri.Scheme}://{baseUri.Host}";
            }
            else
            {
                result = $"{baseUri.Scheme}://{baseUri.Host}:{baseUri.Port}";
            }
        }

        return Task.FromResult(result);
    }
}
