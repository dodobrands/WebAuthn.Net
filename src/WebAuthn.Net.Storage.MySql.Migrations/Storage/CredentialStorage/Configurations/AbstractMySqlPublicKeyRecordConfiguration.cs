using System;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Enums;
using WebAuthn.Net.Storage.MySql.Migrations.Storage.CredentialStorage.Models;

namespace WebAuthn.Net.Storage.MySql.Migrations.Storage.CredentialStorage.Configurations;

public class AbstractMySqlPublicKeyRecordConfiguration : IEntityTypeConfiguration<AbstractMySqlPublicKeyRecord>
{
    public void Configure(EntityTypeBuilder<AbstractMySqlPublicKeyRecord> builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.HasCharSet("utf8mb4", DelegationModes.ApplyToTables);
        builder.UseCollation("utf8mb4_0900_ai_ci", DelegationModes.ApplyToTables);
        builder.HasKey(x => x.UserCredentialRecordId);
        builder.Property(x => x.UserCredentialRecordId)
            .IsFixedLength();

        builder
            .HasDiscriminator(x => x.Kty)
            .HasValue<MySqlCredentialPublicKeyEc2ParametersRecord>((int) CoseKeyType.EC2)
            .HasValue<MySqlCredentialPublicKeyRsaParametersRecord>((int) CoseKeyType.RSA)
            .IsComplete();
    }
}
