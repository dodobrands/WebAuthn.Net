using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using WebAuthn.Net.Mysql.Infrastructure;
using WebAuthn.Net.Mysql.Models;
using WebAuthn.Net.Mysql.Services.Context;
using WebAuthn.Net.Mysql.Storage;
using WebAuthn.Net.Services.Context;
using WebAuthn.Net.Storage.AuthenticationCeremony;
using WebAuthn.Net.Storage.Credential;
using WebAuthn.Net.Storage.RegistrationCeremony;

namespace WebAuthn.Net.Mysql;

public static class MysqlStorageExtensions
{
    public static IServiceCollection AddDefaultWebAuthnMySqlStorage(
        this IServiceCollection service,
        string connectionString,
        string migrationsConnectionString)
    {
        service.TryAddSingleton<IDbConnectionFactory>(new WebauthnMySqlConnectionFactory(connectionString, migrationsConnectionString));
        service.TryAddSingleton<IWebAuthnContextFactory<MySqlWebAuthnContext>, DefaultMySqlContextFactory>();
        service.AddCoreWebAuthnMySqlStorage<MySqlWebAuthnContext>();

        return service;
    }

    public static IServiceCollection AddCoreWebAuthnMySqlStorage<TContext>(
        this IServiceCollection service)
        where TContext : MySqlWebAuthnContext
    {
        service.TryAddSingleton<IAuthenticationCeremonyStorage<TContext>, MysqlAuthenticationCeremonyStorage<TContext>>();
        service.TryAddSingleton<IRegistrationCeremonyStorage<TContext>, MysqlRegistrationCeremonyStorage<TContext>>();
        service.TryAddSingleton<ICredentialStorage<TContext>, MysqlCredentialStorage<TContext>>();
        return service;
    }
}
