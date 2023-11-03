using FluentMigrator;

namespace WebAuthn.Net.Mysql.Migrations;

[Migration(2023_11_03_13_59)]
public class InitialMigration : AutoReversingMigration
{
    public override void Up()
    {
        Create.Table("AuthenticationCeremonies")
            .WithColumn("Id").AsGuid().PrimaryKey()
            .WithColumn("UserHandle").AsBinary().Nullable()
            .WithColumn("Options").AsCustom("JSON").NotNullable()
            .WithColumn("ExpectedRp").AsCustom("JSON").NotNullable()
            .WithColumn("CreatedAt").AsDateTimeOffset().NotNullable()
            .WithColumn("ExpiresAt").AsDateTimeOffset().NotNullable();

        Create.Table("RegistrationCeremonies")
            .WithColumn("Id").AsGuid().PrimaryKey()
            .WithColumn("Options").AsCustom("JSON").NotNullable()
            .WithColumn("ExpectedRp").AsCustom("JSON").NotNullable()
            .WithColumn("CreatedAt").AsDateTimeOffset().NotNullable()
            .WithColumn("ExpiresAt").AsDateTimeOffset().NotNullable();

        Create.Table("UserCredentials")
            .WithColumn("Id").AsGuid().PrimaryKey()
            .WithColumn("UserHandle").AsBinary().NotNullable()
            .WithColumn("RpId").AsString().NotNullable()
            .WithColumn("CredentialRecord").AsCustom("JSON").NotNullable();


        Create.Table("Metadata")
            .WithColumn("Id").AsGuid().PrimaryKey()
            .WithColumn("Metadata").AsCustom("JSON").NotNullable();
    }
}
