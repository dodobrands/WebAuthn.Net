using System.Diagnostics.CodeAnalysis;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using MySqlConnector;
using Pomelo.EntityFrameworkCore.MySql.Infrastructure;
using Pomelo.EntityFrameworkCore.MySql.Storage.Internal;

namespace WebAuthn.Net.Storage.MySql.Migrations.Storage.CredentialStorage;

public class DesignTimeMySqlCredentialStorageDbContextFactory : IDesignTimeDbContextFactory<MySqlCredentialStorageDbContext>
{
    [SuppressMessage("Usage", "EF1001:Internal EF Core API usage.")]
    public MySqlCredentialStorageDbContext CreateDbContext(string[] args)
    {
        var defaultConnectionString = new MySqlConnectionStringBuilder
        {
            Server = "localhost",
            UserID = "root",
            Password = "root",
            Database = "webauthn"
        };
        var builder = new DbContextOptionsBuilder<MySqlCredentialStorageDbContext>();
        builder.UseMySql(
            defaultConnectionString.ConnectionString,
            ServerVersion.Create(8, 0, 15, ServerType.MySql),
            mysql =>
            {
                mysql
                    .UseMicrosoftJson(MySqlJsonChangeTrackingOptions.None)
                    .MigrationsAssembly(typeof(DesignTimeMySqlCredentialStorageDbContextFactory).Assembly.GetName().Name);
            });
        return new(builder.Options);
    }
}
