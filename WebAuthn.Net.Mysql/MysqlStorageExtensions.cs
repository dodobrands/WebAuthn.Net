using System.Reflection;
using Microsoft.Extensions.DependencyInjection;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Mysql.Infrastructure;
using WebAuthn.Net.Mysql.Storage;
using WebAuthn.Net.Storage.AuthenticationCeremony;
using WebAuthn.Net.Storage.Credential;
using WebAuthn.Net.Storage.FidoMetadata;
using WebAuthn.Net.Storage.RegistrationCeremony;

namespace WebAuthn.Net.Mysql;

public static class MysqlStorageExtensions
{
    public static IServiceCollection AddWebauthnMysqlStorage(
        this IServiceCollection service,
        string connectionString,
        Assembly[]? migrationAssembliesOverride
    )
    {
        var migrationAssemblies = migrationAssembliesOverride ?? new[] { typeof(MysqlStorageExtensions).Assembly };
        service.AddSingleton<IAuthenticationCeremonyStorage<IWebAuthnContext>, MysqlAuthenticationCeremonyStorage>();
        service.AddSingleton<IRegistrationCeremonyStorage<IWebAuthnContext>, MysqlRegistrationCeremonyStorage>();
        service.AddSingleton<ICredentialStorage<IWebAuthnContext>, MysqlCredentialStorage>();
        service.AddSingleton<IFidoMetadataStorage, MysqlFidoMetadataStorage>();
        service.AddMySqlMigrations(connectionString, migrationAssemblies);
        return service;
    }
}
