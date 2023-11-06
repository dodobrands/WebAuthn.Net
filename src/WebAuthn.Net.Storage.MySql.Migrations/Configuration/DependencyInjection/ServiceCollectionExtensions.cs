using System;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using WebAuthn.Net.Storage.MySql.Configuration.Builder;
using WebAuthn.Net.Storage.MySql.Migrations.Storage.CredentialStorage;
using WebAuthn.Net.Storage.MySql.Models;

namespace WebAuthn.Net.Storage.MySql.Migrations.Configuration.DependencyInjection;

public static class ServiceCollectionExtensions
{
    public static IMySqlWebAuthnBuilder<TContext> AddMySqlMigrationsDbContext<TContext>(
        this IMySqlWebAuthnBuilder<TContext> builder,
        string connectionString,
        ServerVersion serverVersion,
        Action<DbContextOptionsBuilder>? optionsAction = null,
        Action<MySqlDbContextOptionsBuilder>? mySqlOptionsAction = null)
        where TContext : DefaultMySqlContext
    {
        builder.Services.AddDbContext<MySqlCredentialStorageDbContext>(options =>
        {
            optionsAction?.Invoke(options);
            options.UseMySql(connectionString, serverVersion, mySqlOptionsAction);
        });
        return builder;
    }
}
