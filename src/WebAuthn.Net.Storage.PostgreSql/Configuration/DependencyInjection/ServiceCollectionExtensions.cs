using System;
using Dapper;
using Microsoft.Extensions.DependencyInjection;
using WebAuthn.Net.Configuration.DependencyInjection;
using WebAuthn.Net.Configuration.Options;
using WebAuthn.Net.Storage.AuthenticationCeremony.Implementation;
using WebAuthn.Net.Storage.PostgreSql.Configuration.Builder;
using WebAuthn.Net.Storage.PostgreSql.Models;
using WebAuthn.Net.Storage.PostgreSql.Services.ContextFactory;
using WebAuthn.Net.Storage.PostgreSql.Services.Dapper;
using WebAuthn.Net.Storage.PostgreSql.Storage;
using WebAuthn.Net.Storage.RegistrationCeremony.Implementation;

namespace WebAuthn.Net.Storage.PostgreSql.Configuration.DependencyInjection;

public static class ServiceCollectionExtensions
{
    public static IPostgreSqlWebAuthnBuilder<DefaultPostgreSqlContext> AddWebAuthnPostgreSql(
        this IServiceCollection services,
        Action<WebAuthnOptions>? configureCore = null,
        Action<DefaultCookieRegistrationCeremonyStorageOptions>? configureRegistration = null,
        Action<DefaultCookieAuthenticationCeremonyStorageOptions>? configureAuthentication = null,
        Action<DefaultPostgreSqlContext>? configurePostgreSql = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        services
            .AddWebAuthnCore<DefaultPostgreSqlContext>(configureCore)
            .AddDefaultStorages(configureRegistration, configureAuthentication)
            .AddContextFactory<DefaultPostgreSqlContext, DefaultPostgreSqlContextFactory>()
            .AddCredentialStorage<DefaultPostgreSqlContext, DefaultPostgreSqlSeverCredentialStorage<DefaultPostgreSqlContext>>();

        SqlMapper.AddTypeHandler(new GenericArrayHandler<int>());

        return new PostgreSqlWebAuthnBuilder<DefaultPostgreSqlContext>(services)
            .AddPostgreSqlCoreServices(configurePostgreSql);
    }
}
