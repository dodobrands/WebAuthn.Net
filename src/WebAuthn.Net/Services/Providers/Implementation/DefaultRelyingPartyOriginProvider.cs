﻿using System;
using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Models.Abstractions;

namespace WebAuthn.Net.Services.Providers.Implementation;

public class DefaultRelyingPartyOriginProvider<TContext> : IRelyingPartyOriginProvider<TContext>
    where TContext : class, IWebAuthnContext
{
    public Task<string> GetAsync(TContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();
        var baseAddress = context.HttpContext.Request.Scheme + Uri.SchemeDelimiter + context.HttpContext.Request.Host + context.HttpContext.Request.PathBase;
        var baseUri = new Uri(baseAddress, UriKind.Absolute);
        if (baseUri.Scheme != Uri.UriSchemeHttp && baseUri.Scheme != Uri.UriSchemeHttps)
        {
            throw new InvalidOperationException($"Invalid request scheme. Only '{Uri.UriSchemeHttp}' and '{Uri.UriSchemeHttps}' are allowed.");
        }

        var result = baseUri.IsDefaultPort
            ? $"{baseUri.Scheme}://{baseUri.Host}"
            : $"{baseUri.Scheme}://{baseUri.Host}:{baseUri.Port}";
        return Task.FromResult(result);
    }
}