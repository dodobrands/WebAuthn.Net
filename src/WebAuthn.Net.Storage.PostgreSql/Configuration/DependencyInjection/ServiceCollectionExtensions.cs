using System;
using Microsoft.Extensions.DependencyInjection;
using WebAuthn.Net.Configuration.DependencyInjection;
using WebAuthn.Net.Configuration.Options;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataBackgroundIngest;
using WebAuthn.Net.Storage.AuthenticationCeremony.Implementation;
using WebAuthn.Net.Storage.PostgreSql.Configuration.Builder;
using WebAuthn.Net.Storage.PostgreSql.Configuration.Options;
using WebAuthn.Net.Storage.PostgreSql.Models;
using WebAuthn.Net.Storage.PostgreSql.Services.ContextFactory;
using WebAuthn.Net.Storage.PostgreSql.Storage;
using WebAuthn.Net.Storage.RegistrationCeremony.Implementation;

namespace WebAuthn.Net.Storage.PostgreSql.Configuration.DependencyInjection;

public static class ServiceCollectionExtensions
{
    public static IPostgreSqlWebAuthnBuilder<DefaultPostgreSqlContext> AddWebAuthnPostgreSql(
        this IServiceCollection services,
        Action<WebAuthnOptions>? configure = null,
        Action<IHttpClientBuilder>? configureFidoHttpClientBuilder = null,
        Action<FidoMetadataBackgroundIngestHostedServiceOptions>? configureBackgroundIngest = null,
        Action<DefaultCookieRegistrationCeremonyStorageOptions>? configureRegistration = null,
        Action<DefaultCookieAuthenticationCeremonyStorageOptions>? configureAuthentication = null,
        Action<PostgreSqlOptions>? configurePostgreSql = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        services
            .AddWebAuthnCore<DefaultPostgreSqlContext>(configure, configureFidoHttpClientBuilder, configureBackgroundIngest)
            .AddDefaultStorages(configureRegistration, configureAuthentication)
            .AddContextFactory<DefaultPostgreSqlContext, DefaultPostgreSqlContextFactory>()
            .AddCredentialStorage<DefaultPostgreSqlContext, DefaultPostgreSqlCredentialStorage<DefaultPostgreSqlContext>>();

        services.AddOptions<PostgreSqlOptions>();
        if (configurePostgreSql is not null)
        {
            services.Configure(configurePostgreSql);
        }

        return new PostgreSqlWebAuthnBuilder<DefaultPostgreSqlContext>(services);
    }
}
