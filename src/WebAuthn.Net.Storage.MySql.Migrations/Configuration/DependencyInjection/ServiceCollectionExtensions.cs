using System;
using System.Diagnostics.CodeAnalysis;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Pomelo.EntityFrameworkCore.MySql.Storage.Internal;
using WebAuthn.Net.Storage.MySql.Configuration.Builder;
using WebAuthn.Net.Storage.MySql.Migrations.Storage.CredentialStorage;
using WebAuthn.Net.Storage.MySql.Models;

namespace WebAuthn.Net.Storage.MySql.Migrations.Configuration.DependencyInjection;

public static class ServiceCollectionExtensions
{
    [SuppressMessage("Usage", "EF1001:Internal EF Core API usage.")]
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
            options.UseMySql(connectionString, serverVersion, mysql =>
            {
                mysql
                    .UseMicrosoftJson(MySqlJsonChangeTrackingOptions.None)
                    .MigrationsAssembly(typeof(DesignTimeMySqlCredentialStorageDbContextFactory).Assembly.GetName().Name);
                mySqlOptionsAction?.Invoke(mysql);
            });
        });
        return builder;
    }
}
