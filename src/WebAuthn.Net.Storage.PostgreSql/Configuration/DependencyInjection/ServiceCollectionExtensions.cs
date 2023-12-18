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

/// <summary>
///     Extension methods for <see cref="IServiceCollection" /> for configuring WebAuthn.Net with PostgreSQL-based storage.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    ///     Adds services for WebAuthn.Net to operate with a ready PostgreSQL-based storage.
    /// </summary>
    /// <param name="services">Service collection.</param>
    /// <param name="configure">An optional delegate for configuring global WebAuthn.Net options.</param>
    /// <param name="configureFidoHttpClientBuilder">
    ///     An optional delegate for configuring the HttpClient that will be used to access the <a href="https://fidoalliance.org/metadata">FIDO Metadata Service</a>. Here you can add retries using
    ///     <a href="https://github.com/App-vNext/Polly">Polly</a>, set timeouts, add your own DelegatingHandlers, or otherwise customize the behavior of HttpClient.
    /// </param>
    /// <param name="configureBackgroundIngest">An optional delegate for configuring the behavior of metadata ingestion from <a href="https://fidoalliance.org/metadata">FIDO Metadata Service</a>.</param>
    /// <param name="configureRegistration">An optional delegate for configuring the behavior of the storage responsible for storing registration ceremony data.</param>
    /// <param name="configureAuthentication">An optional delegate for configuring the behavior of the storage responsible for storing authentication ceremony data.</param>
    /// <param name="configurePostgreSql">An optional delegate for configuring the parameters of PostgreSQL-based storage.</param>
    /// <returns>An instance of <see cref="IPostgreSqlWebAuthnBuilder{DefaultPostgreSqlContext}" />, which includes configured services for working with PostgreSQL-based storage.</returns>
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
