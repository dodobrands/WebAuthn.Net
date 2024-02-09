## WebAuthn.Net.Storage.MySql

This project contains an implementation of interfaces responsible for data storage and is intended for use with MySQL 8.0+. MySQL 5.7 is not supported due to the end of life of this version.

## Database schema

As the library is intended to be integrated into existing applications, they may have different data schema migration policies. This could be EntityFramework, FluentMigrator, or something else. Migrations may be applied either at the start of the application or by a separate executable application that, for example, runs in a Kubernetes cluster's init-container. It's difficult for us to account for all possible deployment and application scenarios. Therefore, we provide a script for creating a schema, but you need to decide and implement how exactly to integrate it.

> [!WARNING]
> Please note that having a **unique index** on the `RpId`, `UserHandle`, and `CredentialId` columns is **required**, as the combination of these property values acts as a descriptor, uniquely identifying the public key.

```mysql
CREATE TABLE `CredentialRecords`
(
    `Id`                        binary(16)      NOT NULL,
    `RpId`                      varchar(256)    NOT NULL,
    `UserHandle`                varbinary(128)  NOT NULL,
    `CredentialId`              varbinary(1024) NOT NULL,
    `Type`                      int             NOT NULL,
    `Kty`                       int             NOT NULL,
    `Alg`                       int             NOT NULL,
    `Ec2Crv`                    int             NULL,
    `Ec2X`                      varbinary(256)  NULL,
    `Ec2Y`                      varbinary(256)  NULL,
    `RsaModulusN`               varbinary(1024) NULL,
    `RsaExponentE`              varbinary(32)   NULL,
    `OkpCrv`                    int             NULL,
    `OkpX`                      varbinary(32)  NULL,
    `SignCount`                 int unsigned    NOT NULL,
    `Transports`                json            NOT NULL,
    `UvInitialized`             tinyint(1)      NOT NULL,
    `BackupEligible`            tinyint(1)      NOT NULL,
    `BackupState`               tinyint(1)      NOT NULL,
    `AttestationObject`         longblob        NULL,
    `AttestationClientDataJson` longblob        NULL,
    `Description`               varchar(200)    NULL,
    `CreatedAtUnixTime`         bigint          NOT NULL,
    `UpdatedAtUnixTime`         bigint          NOT NULL,
    CONSTRAINT `PK_CredentialRecords` PRIMARY KEY (`Id`)
) CHARACTER SET = utf8mb4
  COLLATE = utf8mb4_0900_ai_ci;

CREATE UNIQUE INDEX `IX_CredentialRecords_UserHandle_CredentialId_RpId` ON `CredentialRecords`
(
    `UserHandle`,
    `CredentialId`,
    `RpId`
);

CREATE UNIQUE INDEX `IX_CredentialRecords_CredentialId_RpId` ON `CredentialRecords`
(
     `CredentialId`,
     `RpId`
);
```

## Local dev environment

To start a local test container, execute the following command

```shell
docker run -d -e MYSQL_ROOT_PASSWORD=root -p 3306:3306 mysql:8.0.15
```

Connection string for connecting to the container, the command to start which is presented above.

> [!NOTE]
> Don't forget to change the database name specified in the `Database` parameter to the one you will be using.

```
Server=localhost;Port=3306;User ID=root;Password=root;Database=webauthn;Pooling=True;Default Command Timeout=30
```
