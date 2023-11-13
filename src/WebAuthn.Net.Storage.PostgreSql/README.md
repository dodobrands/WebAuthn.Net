## WebAuthn.Net.Storage.PostgreSql

This project contains an implementation of interfaces responsible for data storage and is intended for use with PostgreSQL 16.0+.

## Database schema

As the library is intended to be integrated into existing applications, they may have different data schema migration policies. This could be EntityFramework, FluentMigrator, or something else. Migrations may be applied either at the start of the application or by a separate executable application that, for example, runs in a Kubernetes cluster's init-container. It's difficult for us to account for all possible deployment and application scenarios. Therefore, we provide a script for creating a schema, but you need to decide and implement how exactly to integrate it.

> [!WARNING]
> Please note that having a **unique index** on the `RpId`, `UserHandle`, and `CredentialId` columns is **required**, as the combination of these property values acts as a descriptor, uniquely identifying the public key.

```postgresql
CREATE TABLE "CredentialRecords" (
 "Id" uuid NOT NULL,
 "RpId" character varying(300) NOT NULL,
 "UserHandle" bytea NOT NULL,
 "CredentialId" bytea NOT NULL,
 "Type" integer NOT NULL,
 "Kty" integer NOT NULL,
 "Alg" integer NOT NULL,
 "EcdsaCrv" integer,
 "EcdsaX" bytea,
 "EcdsaY" bytea,
 "RsaModulusN" bytea,
 "RsaExponentE" bytea,
 "SignCount" bigint NOT NULL,
 "Transports" jsonb NOT NULL,
 "UvInitialized" boolean NOT NULL,
 "BackupEligible" boolean NOT NULL,
 "BackupState" boolean NOT NULL,
 "AttestationObject" bytea,
 "AttestationClientDataJson" bytea,
 "CreatedAtUnixTime" bigint NOT NULL,
 CONSTRAINT "PK_CredentialRecords" PRIMARY KEY ("Id")
);

CREATE UNIQUE INDEX "IX_CredentialRecords_RpId_UserHandle_CredentialId" ON "CredentialRecords" ("RpId", "UserHandle", "CredentialId");
```

## Local dev environment

To start a local test container, execute the following command

```shell
docker run -e POSTGRES_PASSWORD=postgres -p 5432:5432 -d postgres:16.0
```
