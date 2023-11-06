using System;
using Microsoft.Extensions.DependencyInjection;
using WebAuthn.Net.Configuration.DependencyInjection;
using WebAuthn.Net.Configuration.Options;
using WebAuthn.Net.Storage.AuthenticationCeremony.Implementation;
using WebAuthn.Net.Storage.MySql.Configuration.Builder;
using WebAuthn.Net.Storage.MySql.Configuration.Options;
using WebAuthn.Net.Storage.MySql.Models;
using WebAuthn.Net.Storage.MySql.Services.ContextFactory;
using WebAuthn.Net.Storage.MySql.Storage.CredentialStorage;
using WebAuthn.Net.Storage.RegistrationCeremony.Implementation;

namespace WebAuthn.Net.Storage.MySql.Configuration.DependencyInjection;

public static class ServiceCollectionExtensions
{
    public static IMySqlWebAuthnBuilder<DefaultMySqlContext> AddWebAuthnMySql(
        this IServiceCollection services,
        Action<WebAuthnOptions>? configureCore = null,
        Action<DefaultCookieRegistrationCeremonyStorageOptions>? configureRegistration = null,
        Action<DefaultCookieAuthenticationCeremonyStorageOptions>? configureAuthentication = null,
        Action<MySqlOptions>? configureMySql = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        services
            .AddWebAuthnCore<DefaultMySqlContext>(configureCore)
            .AddDefaultStorages(configureRegistration, configureAuthentication)
            .AddContextFactory<DefaultMySqlContext, DefaultMySqlContextFactory>()
            .AddCredentialStorage<DefaultMySqlContext, DefaultMySqlCredentialStorage<DefaultMySqlContext>>();
        return new MySqlWebAuthnBuilder<DefaultMySqlContext>(services)
            .AddMySqlCoreServices(configureMySql);
    }
}
