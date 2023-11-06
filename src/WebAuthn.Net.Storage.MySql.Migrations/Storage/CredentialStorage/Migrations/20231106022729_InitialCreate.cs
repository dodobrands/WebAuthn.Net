using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace WebAuthn.Net.Storage.MySql.Migrations.Storage.CredentialStorage.Migrations
{
    public partial class InitialCreate : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "UserCredentials",
                columns: table => new
                {
                    Id = table.Column<byte[]>(type: "binary(16)", fixedLength: true, maxLength: 16, nullable: false),
                    RpId = table.Column<string>(type: "varchar(300)", maxLength: 300, nullable: false),
                    UserHandle = table.Column<byte[]>(type: "varbinary(300)", maxLength: 300, nullable: false),
                    CredentialId = table.Column<byte[]>(type: "varbinary(1024)", maxLength: 1024, nullable: false),
                    Type = table.Column<int>(type: "int", nullable: false),
                    SignCount = table.Column<uint>(type: "int unsigned", nullable: false),
                    Transports = table.Column<string>(type: "json", nullable: false),
                    UvInitialized = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    BackupEligible = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    BackupState = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    AttestationObject = table.Column<byte[]>(type: "longblob", nullable: true),
                    AttestationClientDataJSON = table.Column<byte[]>(type: "longblob", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_UserCredentials", x => x.Id);
                })
                .Annotation("MySql:CharSet", "utf8mb4")
                .Annotation("Relational:Collation", "utf8mb4_0900_ai_ci");

            migrationBuilder.CreateTable(
                name: "PublicKeys",
                columns: table => new
                {
                    UserCredentialRecordId = table.Column<byte[]>(type: "binary(16)", fixedLength: true, maxLength: 16, nullable: false),
                    Kty = table.Column<int>(type: "int", nullable: false),
                    Alg = table.Column<int>(type: "int", nullable: false),
                    EcdsaCrv = table.Column<int>(type: "int", nullable: true),
                    EcdsaX = table.Column<byte[]>(type: "varbinary(256)", maxLength: 256, nullable: true),
                    EcdsaY = table.Column<byte[]>(type: "varbinary(256)", maxLength: 256, nullable: true),
                    RsaModulusN = table.Column<byte[]>(type: "varbinary(1024)", maxLength: 1024, nullable: true),
                    RsaExponentE = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PublicKeys", x => x.UserCredentialRecordId);
                    table.ForeignKey(
                        name: "FK_PublicKeys_UserCredentials_UserCredentialRecordId",
                        column: x => x.UserCredentialRecordId,
                        principalTable: "UserCredentials",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                })
                .Annotation("MySql:CharSet", "utf8mb4")
                .Annotation("Relational:Collation", "utf8mb4_0900_ai_ci");

            migrationBuilder.CreateIndex(
                name: "IX_UserCredentials_RpId_UserHandle_CredentialId",
                table: "UserCredentials",
                columns: new[] { "RpId", "UserHandle", "CredentialId" },
                unique: true);
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "PublicKeys");

            migrationBuilder.DropTable(
                name: "UserCredentials");
        }
    }
}
