using System;
using Microsoft.Extensions.DependencyInjection.Extensions;
using WebAuthn.Net.Configuration.Builder;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Services.Context;
using WebAuthn.Net.Storage.AuthenticationCeremony;
using WebAuthn.Net.Storage.RegistrationCeremony;

namespace WebAuthn.Net.Configuration.DependencyInjection;

public static class WebAuthnBuilderExtensions
{
    public static IWebAuthnBuilder<TContext> AddAuthenticationCeremonyStorage<TContext, TAuthenticationCeremonyStorage>(
        this WebAuthnBuilder<TContext> builder)
        where TContext : class, IWebAuthnContext
        where TAuthenticationCeremonyStorage : class, IAuthenticationCeremonyStorage<TContext>
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.TryAddSingleton<IAuthenticationCeremonyStorage<TContext>, TAuthenticationCeremonyStorage>();
        return builder;
    }

    public static IWebAuthnBuilder<TContext> AddRegistrationCeremonyStorage<TContext, TRegistrationCeremonyOptionsStorage>(
        this WebAuthnBuilder<TContext> builder)
        where TContext : class, IWebAuthnContext
        where TRegistrationCeremonyOptionsStorage : class, IRegistrationCeremonyStorage<TContext>
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.TryAddSingleton<IRegistrationCeremonyStorage<TContext>, TRegistrationCeremonyOptionsStorage>();
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
