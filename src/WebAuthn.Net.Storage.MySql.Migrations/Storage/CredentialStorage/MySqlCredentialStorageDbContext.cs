using System;
using Microsoft.EntityFrameworkCore;
using WebAuthn.Net.Storage.MySql.Migrations.Storage.CredentialStorage.Configurations;
using WebAuthn.Net.Storage.MySql.Models;

namespace WebAuthn.Net.Storage.MySql.Migrations.Storage.CredentialStorage;

public class MySqlCredentialStorageDbContext : DbContext
{
    protected MySqlCredentialStorageDbContext()
    {
    }

    public MySqlCredentialStorageDbContext(DbContextOptions<MySqlCredentialStorageDbContext> options) : base(options)
    {
    }

    public DbSet<MySqlUserCredentialRecord> CredentialRecords { get; set; } = null!;

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        ArgumentNullException.ThrowIfNull(modelBuilder);
        base.OnModelCreating(modelBuilder);
        modelBuilder.UseCollation(null, DelegationModes.ApplyToDatabases);
        modelBuilder.ApplyConfiguration(new MySqlUserCredentialRecordConfiguration());
    }
}
