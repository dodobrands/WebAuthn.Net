﻿// <auto-generated />
using System;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using WebAuthn.Net.Storage.MySql.Migrations.Storage.CredentialStorage;

#nullable disable

namespace WebAuthn.Net.Storage.MySql.Migrations.Storage.CredentialStorage.Migrations
{
    [DbContext(typeof(MySqlCredentialStorageDbContext))]
    [Migration("20231106022729_InitialCreate")]
    partial class InitialCreate
    {
        protected override void BuildTargetModel(ModelBuilder modelBuilder)
        {
#pragma warning disable 612, 618
            modelBuilder
                .HasAnnotation("ProductVersion", "6.0.24")
                .HasAnnotation("Relational:MaxIdentifierLength", 64);

            MySqlModelBuilderExtensions.UseCollation(modelBuilder, null, DelegationModes.ApplyToDatabases);

            modelBuilder.Entity("WebAuthn.Net.Storage.MySql.Migrations.Storage.CredentialStorage.Models.AbstractMySqlPublicKeyRecord", b =>
                {
                    b.Property<byte[]>("UserCredentialRecordId")
                        .HasMaxLength(16)
                        .HasColumnType("binary(16)")
                        .IsFixedLength();

                    b.Property<int>("Alg")
                        .HasColumnType("int");

                    b.Property<int>("Kty")
                        .HasColumnType("int");

                    b.HasKey("UserCredentialRecordId");

                    b.ToTable("PublicKeys");

                    b.HasDiscriminator<int>("Kty").IsComplete(true);

                    MySqlEntityTypeBuilderExtensions.HasCharSet(b, "utf8mb4", DelegationModes.ApplyToTables);
                    MySqlEntityTypeBuilderExtensions.UseCollation(b, "utf8mb4_0900_ai_ci", DelegationModes.ApplyToTables);
                });

            modelBuilder.Entity("WebAuthn.Net.Storage.MySql.Migrations.Storage.CredentialStorage.Models.MySqlUserCredentialRecord", b =>
                {
                    b.Property<byte[]>("Id")
                        .HasMaxLength(16)
                        .HasColumnType("binary(16)")
                        .IsFixedLength();

                    b.Property<byte[]>("AttestationClientDataJSON")
                        .HasColumnType("longblob");

                    b.Property<byte[]>("AttestationObject")
                        .HasColumnType("longblob");

                    b.Property<bool>("BackupEligible")
                        .HasColumnType("tinyint(1)");

                    b.Property<bool>("BackupState")
                        .HasColumnType("tinyint(1)");

                    b.Property<byte[]>("CredentialId")
                        .IsRequired()
                        .HasMaxLength(1024)
                        .HasColumnType("varbinary(1024)");

                    b.Property<string>("RpId")
                        .IsRequired()
                        .HasMaxLength(300)
                        .HasColumnType("varchar(300)");

                    b.Property<uint>("SignCount")
                        .HasColumnType("int unsigned");

                    b.Property<string>("Transports")
                        .IsRequired()
                        .HasColumnType("json");

                    b.Property<int>("Type")
                        .HasColumnType("int");

                    b.Property<byte[]>("UserHandle")
                        .IsRequired()
                        .HasMaxLength(300)
                        .HasColumnType("varbinary(300)");

                    b.Property<bool>("UvInitialized")
                        .HasColumnType("tinyint(1)");

                    b.HasKey("Id");

                    b.HasIndex("RpId", "UserHandle", "CredentialId")
                        .IsUnique();

                    b.ToTable("UserCredentials");

                    MySqlEntityTypeBuilderExtensions.HasCharSet(b, "utf8mb4", DelegationModes.ApplyToTables);
                    MySqlEntityTypeBuilderExtensions.UseCollation(b, "utf8mb4_0900_ai_ci", DelegationModes.ApplyToTables);
                });

            modelBuilder.Entity("WebAuthn.Net.Storage.MySql.Migrations.Storage.CredentialStorage.Models.MySqlCredentialPublicKeyEc2ParametersRecord", b =>
                {
                    b.HasBaseType("WebAuthn.Net.Storage.MySql.Migrations.Storage.CredentialStorage.Models.AbstractMySqlPublicKeyRecord");

                    b.Property<int>("Crv")
                        .HasColumnType("int")
                        .HasColumnName("EcdsaCrv");

                    b.Property<byte[]>("X")
                        .IsRequired()
                        .HasMaxLength(256)
                        .HasColumnType("varbinary(256)")
                        .HasColumnName("EcdsaX");

                    b.Property<byte[]>("Y")
                        .IsRequired()
                        .HasMaxLength(256)
                        .HasColumnType("varbinary(256)")
                        .HasColumnName("EcdsaY");

                    b.HasDiscriminator().HasValue(2);
                });

            modelBuilder.Entity("WebAuthn.Net.Storage.MySql.Migrations.Storage.CredentialStorage.Models.MySqlCredentialPublicKeyRsaParametersRecord", b =>
                {
                    b.HasBaseType("WebAuthn.Net.Storage.MySql.Migrations.Storage.CredentialStorage.Models.AbstractMySqlPublicKeyRecord");

                    b.Property<byte[]>("ExponentE")
                        .IsRequired()
                        .HasMaxLength(32)
                        .HasColumnType("varbinary(32)")
                        .HasColumnName("RsaExponentE");

                    b.Property<byte[]>("ModulusN")
                        .IsRequired()
                        .HasMaxLength(1024)
                        .HasColumnType("varbinary(1024)")
                        .HasColumnName("RsaModulusN");

                    b.HasDiscriminator().HasValue(3);
                });

            modelBuilder.Entity("WebAuthn.Net.Storage.MySql.Migrations.Storage.CredentialStorage.Models.AbstractMySqlPublicKeyRecord", b =>
                {
                    b.HasOne("WebAuthn.Net.Storage.MySql.Migrations.Storage.CredentialStorage.Models.MySqlUserCredentialRecord", "UserCredentialRecord")
                        .WithOne("PublicKey")
                        .HasForeignKey("WebAuthn.Net.Storage.MySql.Migrations.Storage.CredentialStorage.Models.AbstractMySqlPublicKeyRecord", "UserCredentialRecordId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired();

                    b.Navigation("UserCredentialRecord");
                });

            modelBuilder.Entity("WebAuthn.Net.Storage.MySql.Migrations.Storage.CredentialStorage.Models.MySqlUserCredentialRecord", b =>
                {
                    b.Navigation("PublicKey")
                        .IsRequired();
                });
#pragma warning restore 612, 618
        }
    }
}
