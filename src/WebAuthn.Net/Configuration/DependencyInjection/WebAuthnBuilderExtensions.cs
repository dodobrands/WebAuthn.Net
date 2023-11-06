using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using WebAuthn.Net.Configuration.Builder;
using WebAuthn.Net.Configuration.Options;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Services.Common.AuthenticatorDataDecoder;
using WebAuthn.Net.Services.Common.AuthenticatorDataDecoder.Implementation;
using WebAuthn.Net.Services.Common.ChallengeGenerator;
using WebAuthn.Net.Services.Common.ChallengeGenerator.Implementation;
using WebAuthn.Net.Services.Context;
using WebAuthn.Net.Services.Providers;
using WebAuthn.Net.Services.Providers.Implementation;
using WebAuthn.Net.Services.RegistrationCeremony;
using WebAuthn.Net.Services.RegistrationCeremony.Implementation;
using WebAuthn.Net.Storage.AuthenticationCeremony;
using WebAuthn.Net.Storage.AuthenticationCeremony.Implementation;
using WebAuthn.Net.Storage.Credential;
using WebAuthn.Net.Storage.FidoMetadata;
using WebAuthn.Net.Storage.FidoMetadata.Implementation;
using WebAuthn.Net.Storage.RegistrationCeremony;
using WebAuthn.Net.Storage.RegistrationCeremony.Implementation;

namespace WebAuthn.Net.Configuration.DependencyInjection;

public static class WebAuthnBuilderExtensions
{
    public static IWebAuthnBuilder<TContext> AddCoreServices<TContext>(
        this IWebAuthnBuilder<TContext> builder,
        Action<WebAuthnOptions>? configure = null)
        where TContext : class, IWebAuthnContext
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.AddOptions<WebAuthnOptions>();
        if (configure is not null)
        {
            builder.Services.Configure(configure);
        }

        builder.Services.TryAddSingleton<IAuthenticatorDataDecoder, DefaultAuthenticatorDataDecoder>();
        builder.Services.TryAddSingleton<IChallengeGenerator, DefaultChallengeGenerator>();
        builder.Services.TryAddSingleton<IRegistrationCeremonyService, DefaultRegistrationCeremonyService<TContext>>();
        builder.Services.TryAddSingleton<ITimeProvider, DefaultTimeProvider>();
        return builder;
    }

    public static IWebAuthnBuilder<TContext> AddDefaultStorages<TContext>(
        this IWebAuthnBuilder<TContext> builder,
        Action<DefaultCookieRegistrationCeremonyStorageOptions>? configureRegistration = null,
        Action<DefaultCookieAuthenticationCeremonyStorageOptions>? configureAuthentication = null)
        where TContext : class, IWebAuthnContext
    {
        ArgumentNullException.ThrowIfNull(builder);
        return builder
            .AddDefaultRegistrationCeremonyStorage(configureRegistration)
            .AddDefaultAuthenticationCeremonyStorage(configureAuthentication)
            .AddDefaultFidoMetadataStorage();
    }

    public static IWebAuthnBuilder<TContext> AddDefaultRegistrationCeremonyStorage<TContext>(
        this IWebAuthnBuilder<TContext> builder,
        Action<DefaultCookieRegistrationCeremonyStorageOptions>? configure = null)
        where TContext : class, IWebAuthnContext
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.AddOptions<DefaultCookieRegistrationCeremonyStorageOptions>();
        if (configure is not null)
        {
            builder.Services.Configure(configure);
        }

        return builder.AddRegistrationCeremonyStorage<TContext, DefaultCookieRegistrationCeremonyStorage<TContext>>();
    }

    public static IWebAuthnBuilder<TContext> AddDefaultAuthenticationCeremonyStorage<TContext>(
        this IWebAuthnBuilder<TContext> builder,
        Action<DefaultCookieAuthenticationCeremonyStorageOptions>? configure = null)
        where TContext : class, IWebAuthnContext
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.AddOptions<DefaultCookieAuthenticationCeremonyStorageOptions>();
        if (configure is not null)
        {
            builder.Services.Configure(configure);
        }

        return builder.AddAuthenticationCeremonyStorage<TContext, DefaultCookieAuthenticationCeremonyStorage<TContext>>();
    }

    public static IWebAuthnBuilder<TContext> AddDefaultFidoMetadataStorage<TContext>(
        this IWebAuthnBuilder<TContext> builder)
        where TContext : class, IWebAuthnContext
    {
        ArgumentNullException.ThrowIfNull(builder);
        return builder.AddFidoMetadataStorage<TContext, DefaultInMemoryFidoMetadataStorage<TContext>>();
    }

    public static IWebAuthnBuilder<TContext> AddRegistrationCeremonyStorage<TContext, TRegistrationCeremonyStorageImpl>(
        this IWebAuthnBuilder<TContext> builder)
        where TContext : class, IWebAuthnContext
        where TRegistrationCeremonyStorageImpl : class, IRegistrationCeremonyStorage<TContext>
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.TryAddSingleton<IRegistrationCeremonyStorage<TContext>, TRegistrationCeremonyStorageImpl>();
        return builder;
    }

    public static IWebAuthnBuilder<TContext> AddAuthenticationCeremonyStorage<TContext, TAuthenticationCeremonyStorageImpl>(
        this IWebAuthnBuilder<TContext> builder)
        where TContext : class, IWebAuthnContext
        where TAuthenticationCeremonyStorageImpl : class, IAuthenticationCeremonyStorage<TContext>
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.TryAddSingleton<IAuthenticationCeremonyStorage<TContext>, TAuthenticationCeremonyStorageImpl>();
        return builder;
    }

    public static IWebAuthnBuilder<TContext> AddCredentialStorage<TContext, TCredentialStorageImpl>(
        this IWebAuthnBuilder<TContext> builder)
        where TContext : class, IWebAuthnContext
        where TCredentialStorageImpl : class, ICredentialStorage<TContext>
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.TryAddSingleton<ICredentialStorage<TContext>, TCredentialStorageImpl>();
        return builder;
    }

    public static IWebAuthnBuilder<TContext> AddFidoMetadataStorage<TContext, TFidoMetadataStorageImpl>(
        this IWebAuthnBuilder<TContext> builder)
        where TContext : class, IWebAuthnContext
        where TFidoMetadataStorageImpl : class, IFidoMetadataStorage<TContext>
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.TryAddSingleton<IFidoMetadataStorage<TContext>, TFidoMetadataStorageImpl>();
        return builder;
    }

    public static IWebAuthnBuilder<TContext> AddContextFactory<TContext, TContextFactoryImpl>(
        this IWebAuthnBuilder<TContext> builder)
        where TContext : class, IWebAuthnContext
        where TContextFactoryImpl : class, IWebAuthnContextFactory<TContext>
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.TryAddSingleton<IWebAuthnContextFactory<TContext>, TContextFactoryImpl>();
        return builder;
    }
}
