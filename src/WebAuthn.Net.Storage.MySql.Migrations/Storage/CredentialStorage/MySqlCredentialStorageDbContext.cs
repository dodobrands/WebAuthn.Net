using System;
using Microsoft.EntityFrameworkCore;
using WebAuthn.Net.Storage.MySql.Migrations.Storage.CredentialStorage.Configurations;
using WebAuthn.Net.Storage.MySql.Migrations.Storage.CredentialStorage.Models;

namespace WebAuthn.Net.Storage.MySql.Migrations.Storage.CredentialStorage;

public class MySqlCredentialStorageDbContext : DbContext
{
    protected MySqlCredentialStorageDbContext()
    {
    }

    public MySqlCredentialStorageDbContext(DbContextOptions options) : base(options)
    {
    }

    public DbSet<MySqlUserCredentialRecord> UserCredentials { get; set; } = null!;
    public DbSet<AbstractMySqlPublicKeyRecord> PublicKeys { get; set; } = null!;

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        ArgumentNullException.ThrowIfNull(modelBuilder);
        base.OnModelCreating(modelBuilder);
        modelBuilder.UseCollation(null, DelegationModes.ApplyToDatabases);
        modelBuilder.ApplyConfiguration(new MySqlUserCredentialRecordConfiguration());
        modelBuilder.ApplyConfiguration(new AbstractMySqlPublicKeyRecordConfiguration());
    }
}
