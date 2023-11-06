using System;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using WebAuthn.Net.Storage.MySql.Migrations.Storage.CredentialStorage.Models;

namespace WebAuthn.Net.Storage.MySql.Migrations.Storage.CredentialStorage.Configurations;

public class MySqlUserCredentialRecordConfiguration : IEntityTypeConfiguration<MySqlUserCredentialRecord>
{
    public void Configure(EntityTypeBuilder<MySqlUserCredentialRecord> builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.HasCharSet("utf8mb4", DelegationModes.ApplyToTables);
        builder.UseCollation("utf8mb4_0900_ai_ci", DelegationModes.ApplyToTables);
        builder.HasKey(x => x.Id);
        builder.Property(x => x.Id)
            .IsFixedLength();
        builder.HasIndex(x => new
        {
            x.RpId,
            x.UserHandle,
            x.CredentialId
        }).IsUnique();
        builder.Property(x => x.Type);
        builder.HasOne(x => x.PublicKey)
            .WithOne(x => x.UserCredentialRecord)
            .HasForeignKey<AbstractMySqlPublicKeyRecord>(x => x.UserCredentialRecordId)
            .OnDelete(DeleteBehavior.Cascade);
        builder.Property(x => x.Transports)
            .IsRequired()
            .HasColumnType("json");
    }
}
