using System;
using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Models.Abstractions;

namespace WebAuthn.Net.Services.Providers.Implementation;

public class DefaultRelyingPartyIdProvider<TContext> : IRelyingPartyIdProvider<TContext>
    where TContext : class, IWebAuthnContext
{
    public Task<string> GetAsync(TContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();
        var baseAddress = context.HttpContext.Request.Scheme + Uri.SchemeDelimiter + context.HttpContext.Request.Host + context.HttpContext.Request.PathBase;
        var baseUri = new Uri(baseAddress, UriKind.Absolute);
        var effectiveDomain = baseUri.Host;
        return Task.FromResult(effectiveDomain);
    }
}
