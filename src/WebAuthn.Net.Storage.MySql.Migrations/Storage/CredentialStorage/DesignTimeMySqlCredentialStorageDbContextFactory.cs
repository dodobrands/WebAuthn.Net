using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using MySqlConnector;
using Pomelo.EntityFrameworkCore.MySql.Infrastructure;

namespace WebAuthn.Net.Storage.MySql.Migrations.Storage.CredentialStorage;

public class DesignTimeMySqlCredentialStorageDbContextFactory : IDesignTimeDbContextFactory<MySqlCredentialStorageDbContext>
{
    public MySqlCredentialStorageDbContext CreateDbContext(string[] args)
    {
        var defaultConnectionString = new MySqlConnectionStringBuilder
        {
            Server = "localhost",
            UserID = "root",
            Password = "root",
            Database = "webauthn"
        };
        var builder = new DbContextOptionsBuilder();
        builder.UseMySql(
            defaultConnectionString.ConnectionString,
            ServerVersion.Create(8, 0, 35, ServerType.MySql),
            options =>
            {
                options
                    .EnableIndexOptimizedBooleanColumns()
                    .UseMicrosoftJson();
            });
        return new(builder.Options);
    }
}
