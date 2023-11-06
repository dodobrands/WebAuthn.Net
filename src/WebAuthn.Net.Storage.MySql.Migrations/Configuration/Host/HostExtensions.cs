using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using WebAuthn.Net.Storage.MySql.Migrations.Storage.CredentialStorage;

namespace WebAuthn.Net.Storage.MySql.Migrations.Configuration.Host;

public static class HostExtensions
{
    public static IHost ApplyWebAuthnMySqlMigrations(this IHost host, bool ensureDatabaseCreated = true)
    {
        using var scope = host.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<MySqlCredentialStorageDbContext>();
        if (ensureDatabaseCreated)
        {
            db.Database.EnsureCreated();
        }

        db.Database.Migrate();
        return host;
    }
}
