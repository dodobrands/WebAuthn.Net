﻿using System;
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
        return Task.FromResult(context.HttpContext.Request.Host.ToString());
    }
}
