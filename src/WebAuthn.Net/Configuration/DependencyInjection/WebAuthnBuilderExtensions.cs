using System;
using Microsoft.Extensions.DependencyInjection.Extensions;
using WebAuthn.Net.Configuration.Builder;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Services.Context;
using WebAuthn.Net.Storage.Operations;

namespace WebAuthn.Net.Configuration.DependencyInjection;

public static class WebAuthnBuilderExtensions
{
    public static IWebAuthnBuilder<TContext> AddOperationalStorage<TContext, TOperationalStorage>(
        this WebAuthnBuilder<TContext> builder)
        where TContext : class, IWebAuthnContext
        where TOperationalStorage : class, IOperationalStorage<TContext>
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.TryAddSingleton<IOperationalStorage<TContext>, TOperationalStorage>();
        return builder;
    }

    public static IWebAuthnBuilder<TContext> AddContextFactory<TContext, TContextFactory>(
        this WebAuthnBuilder<TContext> builder)
        where TContext : class, IWebAuthnContext
        where TContextFactory : class, IWebAuthnContextFactory<TContext>
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.TryAddSingleton<IWebAuthnContextFactory<TContext>, TContextFactory>();
        return builder;
    }
}
