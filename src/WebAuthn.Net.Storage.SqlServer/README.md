## WebAuthn.Net.Storage.SqlServer

This project contains an implementation of interfaces responsible for data storage and is intended for use with Microsoft SQL Server 2019+. The project may also work with earlier versions, but integration with them has not been tested.

## Database schema

As the library is intended to be integrated into existing applications, they may have different data schema migration policies. This could be EntityFramework, FluentMigrator, or something else. Migrations may be applied either at the start of the application or by a separate executable application that, for example, runs in a Kubernetes cluster's init-container. It's difficult for us to account for all possible deployment and application scenarios. Therefore, we provide a script for creating a schema, but you need to decide and implement how exactly to integrate it.

> [!WARNING]
> Please note that having a **unique index** on the `RpId`, `UserHandle`, and `CredentialId` columns is **required**, as the combination of these property values acts as a descriptor, uniquely identifying the public key.

> [!WARNING]
> Please note, that the identifier generator creates sequential identifiers, **compatible only with the uniqueidentifier** data type and passed as `System.Guid` parameters in queries. If you use `binary(16)` instead of `uniqueidentifier` when creating a table schema for the primary key, you will experience **significant performance degradation**.

```tsql
CREATE TABLE [CredentialRecords]
(
    [Id]                        uniqueidentifier NOT NULL,
    [RpId]                      nvarchar(256)    NOT NULL,
    [UserHandle]                varbinary(128)   NOT NULL,
    [CredentialId]              varbinary(1024)  NOT NULL,
    [Type]                      int              NOT NULL,
    [Kty]                       int              NOT NULL,
    [Alg]                       int              NOT NULL,
    [Ec2Crv]                    int              NULL,
    [Ec2X]                      varbinary(256)   NULL,
    [Ec2Y]                      varbinary(256)   NULL,
    [RsaModulusN]               varbinary(1024)  NULL,
    [RsaExponentE]              varbinary(32)    NULL,
    [OkpCrv]                    int              NULL,
    [OkpX]                      varbinary(32)    NULL,
    [SignCount]                 bigint           NOT NULL,
    [Transports]                nvarchar(max)    NOT NULL,
    [UvInitialized]             bit              NOT NULL,
    [BackupEligible]            bit              NOT NULL,
    [BackupState]               bit              NOT NULL,
    [AttestationObject]         varbinary(max)   NULL,
    [AttestationClientDataJson] varbinary(max)   NULL,
    [Description]               nvarchar(200)    NULL,
    [CreatedAtUnixTime]         bigint           NOT NULL,
    [UpdatedAtUnixTime]         bigint           NOT NULL,
    CONSTRAINT [PK_CredentialRecords] PRIMARY KEY ([Id])
);
ALTER TABLE [CredentialRecords]
    ADD CONSTRAINT [Transports should be formatted as JSON] CHECK (ISJSON(Transports) = 1);
CREATE UNIQUE INDEX [IX_CredentialRecords_UserHandle_CredentialId_RpId] ON [CredentialRecords] ([UserHandle], [CredentialId], [RpId]);
CREATE UNIQUE INDEX [IX_CredentialRecords_CredentialId_RpId] ON [CredentialRecords] ([CredentialId], [RpId]);
```

## Local dev environment

To start a local test container, execute the following command

```shell
docker run -e "ACCEPT_EULA=Y" -e "MSSQL_SA_PASSWORD=WebAuthn!1337" -p 1433:1433 -d mcr.microsoft.com/mssql/server:2019-latest
```

Connection string for connecting to the container, the command to start which is presented above.

> [!NOTE]
> Don't forget to change the database name specified in the `Initial Catalog` parameter to the one you will be using.

```
Data Source=localhost;Initial Catalog=webauthn;User ID=sa;Password=WebAuthn!1337;Pooling=True;Trust Server Certificate=True
```
