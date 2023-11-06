CREATE TABLE IF NOT EXISTS `__EFMigrationsHistory`
(
    `MigrationId`    varchar(150) CHARACTER SET utf8mb4 NOT NULL,
    `ProductVersion` varchar(32) CHARACTER SET utf8mb4  NOT NULL,
    CONSTRAINT `PK___EFMigrationsHistory` PRIMARY KEY (`MigrationId`)
) CHARACTER SET = utf8mb4;

START TRANSACTION;

CREATE TABLE `MySqlUserCredentialRecord`
(
    `Id`                        binary(16)      NOT NULL,
    `RpId`                      varchar(300)    NOT NULL,
    `UserHandle`                varbinary(300)  NOT NULL,
    `CredentialId`              varbinary(1024) NOT NULL,
    `Type`                      int             NOT NULL,
    `Kty`                       int             NOT NULL,
    `Alg`                       int             NOT NULL,
    `EcdsaCrv`                  int             NULL,
    `EcdsaX`                    varbinary(256)  NULL,
    `EcdsaY`                    varbinary(256)  NULL,
    `RsaModulusN`               varbinary(1024) NULL,
    `RsaExponentE`              varbinary(32)   NULL,
    `SignCount`                 int unsigned    NOT NULL,
    `Transports`                json            NOT NULL,
    `UvInitialized`             tinyint(1)      NOT NULL,
    `BackupEligible`            tinyint(1)      NOT NULL,
    `BackupState`               tinyint(1)      NOT NULL,
    `AttestationObject`         longblob        NULL,
    `AttestationClientDataJson` longblob        NULL,
    `CreatedAtUnixTime`         bigint          NOT NULL,
    CONSTRAINT `PK_MySqlUserCredentialRecord` PRIMARY KEY (`Id`)
) CHARACTER SET = utf8mb4
  COLLATE = utf8mb4_0900_ai_ci;

CREATE INDEX `IX_MySqlUserCredentialRecord_RpId_UserHandle` ON `MySqlUserCredentialRecord` (`RpId`, `UserHandle`);

CREATE UNIQUE INDEX `IX_MySqlUserCredentialRecord_RpId_UserHandle_CredentialId` ON `MySqlUserCredentialRecord` (`RpId`, `UserHandle`, `CredentialId`);

INSERT INTO `__EFMigrationsHistory` (`MigrationId`, `ProductVersion`)
VALUES ('20231106221754_InitialCreate', '6.0.24');

COMMIT;

