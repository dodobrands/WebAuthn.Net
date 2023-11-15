﻿using System;
using Microsoft.Extensions.DependencyInjection;
using WebAuthn.Net.Configuration.DependencyInjection;
using WebAuthn.Net.Configuration.Options;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataBackgroundIngest;
using WebAuthn.Net.Storage.AuthenticationCeremony.Implementation;
using WebAuthn.Net.Storage.RegistrationCeremony.Implementation;
using WebAuthn.Net.Storage.SqlServer.Configuration.Builder;
using WebAuthn.Net.Storage.SqlServer.Configuration.Options;
using WebAuthn.Net.Storage.SqlServer.Models;
using WebAuthn.Net.Storage.SqlServer.Services.ContextFactory;
using WebAuthn.Net.Storage.SqlServer.Storage;

namespace WebAuthn.Net.Storage.SqlServer.Configuration.DependencyInjection;

public static class ServiceCollectionExtensions
{
    public static ISqlServerWebAuthnBuilder<DefaultSqlServerContext> AddWebAuthnSqlServer(
        this IServiceCollection services,
        Action<WebAuthnOptions>? configure = null,
        Action<IHttpClientBuilder>? configureFidoHttpClientBuilder = null,
        Action<FidoMetadataBackgroundIngestHostedServiceOptions>? configureBackgroundIngest = null,
        Action<DefaultCookieRegistrationCeremonyStorageOptions>? configureRegistration = null,
        Action<DefaultCookieAuthenticationCeremonyStorageOptions>? configureAuthentication = null,
        Action<DefaultSqlServerContext>? configureSqlServer = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        services
            .AddWebAuthnCore<DefaultSqlServerContext>(configure, configureFidoHttpClientBuilder, configureBackgroundIngest)
            .AddDefaultStorages(configureRegistration, configureAuthentication)
            .AddContextFactory<DefaultSqlServerContext, DefaultSqlServerContextFactory>()
            .AddCredentialStorage<DefaultSqlServerContext, DefaultSqlServerCredentialStorage<DefaultSqlServerContext>>();

        services.AddOptions<SqlServerOptions>();
        if (configureSqlServer is not null)
        {
            services.Configure(configureSqlServer);
        }

        return new SqlServerWebAuthnBuilder<DefaultSqlServerContext>(services);
    }
}
