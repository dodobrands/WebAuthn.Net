using System.Diagnostics.CodeAnalysis;
using FluentMigrator.Runner;

namespace WebAuthn.Net.Mysql.Infrastructure;

[SuppressMessage("ReSharper", "ClassNeverInstantiated.Global")]
public class Migrator
{
    private readonly IDbConnectionFactory _connectionFactory;
    private readonly IMigrationRunner _migrationRunner;

    public Migrator(IMigrationRunner migrationRunner, IDbConnectionFactory connectionFactory)
    {
        _migrationRunner = migrationRunner;
        _connectionFactory = connectionFactory;
    }

    public async Task Run(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _migrationRunner.MigrateUp();
        await Task.Yield();
    }
}
