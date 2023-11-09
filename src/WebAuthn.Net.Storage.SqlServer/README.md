## WebAuthn.Net.Storage.SqlServer

This project contains an implementation of interfaces responsible for data storage and is intended for use with SqlServer 2019+.

## Database schema

As the library is intended to be integrated into existing applications, they may have different data schema migration policies. This could be EntityFramework, FluentMigrator, or something else. Migrations may be applied either at the start of the application or by a separate executable application that, for example, runs in a Kubernetes cluster's init-container. It's difficult for us to account for all possible deployment and application scenarios. Therefore, we provide a script for creating a schema, but you need to decide and implement how exactly to integrate it.

> [!WARNING]
> Please note that having a **unique index** on the `RpId`, `UserHandle`, and `CredentialId` columns is **required**, as the combination of these property values acts as a descriptor, uniquely identifying the public key.

```tsql
CREATE TABLE [CredentialRecords] (
    [Id] uniqueidentifier NOT NULL,
    [RpId] nvarchar(300) NOT NULL,
    [UserHandle] varbinary(300) NOT NULL,
    [CredentialId] varbinary(1024) NOT NULL,
    [Type] int NOT NULL,
    [Kty] int NOT NULL,
    [Alg] int NOT NULL,
    [EcdsaCrv] int NULL,
    [EcdsaX] varbinary(256) NULL,
    [EcdsaY] varbinary(256) NULL,
    [RsaModulusN] varbinary(1024) NULL,
    [RsaExponentE] varbinary(32) NULL,
    [SignCount] bigint NOT NULL,
    [Transports] nvarchar(max) NOT NULL,
    [UvInitialized] bit NOT NULL,
    [BackupEligible] bit NOT NULL,
    [BackupState] bit NOT NULL,
    [AttestationObject] varbinary(max) NULL,
    [AttestationClientDataJson] varbinary(max) NULL,
    [CreatedAtUnixTime] bigint NOT NULL,
    CONSTRAINT [PK_CredentialRecords] PRIMARY KEY ([Id])
);
ALTER TABLE [CredentialRecords] ADD CONSTRAINT [Transports should be formatted as JSON] CHECK (ISJSON(Transports)=1);
CREATE UNIQUE INDEX [IX_CredentialRecords_RpId_UserHandle_CredentialId] ON [CredentialRecords] ([RpId], [UserHandle], [CredentialId]);
```

## Local dev environment

To start a local test container, execute the following command

```shell
docker run -e "ACCEPT_EULA=Y" -e "MSSQL_SA_PASSWORD=RootooR32!" -p 1433:1433 -d mcr.microsoft.com/mssql/server:2019-CU23-ubuntu-20.04
```