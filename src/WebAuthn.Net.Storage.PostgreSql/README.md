## WebAuthn.Net.Storage.PostgreSql

This project contains an implementation of interfaces responsible for data storage and is intended for use with PostgreSQL 16.0+. The project may also work with earlier versions, but integration with them has not been tested.

## Database schema

As the library is intended to be integrated into existing applications, they may have different data schema migration policies. This could be EntityFramework, FluentMigrator, or something else. Migrations may be applied either at the start of the application or by a separate executable application that, for example, runs in a Kubernetes cluster's init-container. It's difficult for us to account for all possible deployment and application scenarios. Therefore, we provide a script for creating a schema, but you need to decide and implement how exactly to integrate it.

> [!WARNING]
> Please note that having a **unique index** on the `RpId`, `UserHandle`, and `CredentialId` columns is **required**, as the combination of these property values acts as a descriptor, uniquely identifying the public key.

```postgresql
CREATE TABLE "CredentialRecords" (
    "Id" uuid NOT NULL,
    "RpId" character varying(256) NOT NULL,
    "UserHandle" bytea NOT NULL,
    "CredentialId" bytea NOT NULL,
    "Type" integer NOT NULL,
    "Kty" integer NOT NULL,
    "Alg" integer NOT NULL,
    "Ec2Crv" integer,
    "Ec2X" bytea,
    "Ec2Y" bytea,
    "RsaModulusN" bytea,
    "RsaExponentE" bytea,
    "OkpCrv" integer,
    "OkpX" bytea,
    "SignCount" bigint NOT NULL,
    "Transports" jsonb NOT NULL,
    "UvInitialized" boolean NOT NULL,
    "BackupEligible" boolean NOT NULL,
    "BackupState" boolean NOT NULL,
    "AttestationObject" bytea,
    "AttestationClientDataJson" bytea,
    "Description" character varying(200),
    "CreatedAtUnixTime" bigint NOT NULL,
    "UpdatedAtUnixTime" bigint NOT NULL,
    CONSTRAINT "PK_CredentialRecords" PRIMARY KEY ("Id")
);

CREATE UNIQUE INDEX "IX_CredentialRecords_UserHandle_CredentialId_RpId" ON "CredentialRecords" ("UserHandle", "CredentialId", "RpId");
CREATE UNIQUE INDEX "IX_CredentialRecords_CredentialId_RpId" ON "CredentialRecords" ("CredentialId", "RpId");
```

## Local dev environment

To start a local test container, execute the following command

```shell
docker run -e POSTGRES_PASSWORD=postgres -p 5432:5432 -d postgres:16.0
```

Connection string for connecting to the container, the command to start which is presented above.

> [!NOTE]
> Don't forget to change the database name specified in the `Database` parameter to the one you will be using.

```
Host=localhost;Port=5432;Password=postgres;Username=postgres;Database=webauthn;Pooling=True
```
