using System.Reflection;
using FluentMigrator.Runner;
using Microsoft.Extensions.DependencyInjection;

namespace WebAuthn.Net.Mysql.Infrastructure;

internal static class MySqlMigratorServiceCollectionExtensions
{
    public static IServiceCollection AddMySqlMigrations(
        this IServiceCollection services,
        string connectionString,
        Assembly[] assemblies)
    {
        if (services == null)
        {
            throw new ArgumentNullException(nameof(services));
        }

        services.AddFluentMigratorCore()
            .ConfigureRunner(runner => runner
                .AddMySql5()
                .WithGlobalConnectionString(connectionString)
                .ScanIn(assemblies).For.Migrations())
            .AddScoped<Migrator>();

        return services;
    }
}
