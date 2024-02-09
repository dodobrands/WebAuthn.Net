using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Dapper;
using WebAuthn.Net.Models.Protocol;
using WebAuthn.Net.Services.Providers;
using WebAuthn.Net.Storage.Credential;
using WebAuthn.Net.Storage.Credential.Models;
using WebAuthn.Net.Storage.MySql.Models;
using WebAuthn.Net.Storage.MySql.Services.Static;
using WebAuthn.Net.Storage.MySql.Storage.CredentialStorage.Models;

namespace WebAuthn.Net.Storage.MySql.Storage.CredentialStorage;

/// <summary>
///     Default implementation of <see cref="ICredentialStorage{TContext}" /> for MySQL-based storage.
/// </summary>
/// <typeparam name="TContext">The type of context in which the WebAuthn operation will be performed. Must be <see cref="DefaultMySqlContext" /> or its descendant.</typeparam>
public class DefaultMySqlCredentialStorage<TContext> : ICredentialStorage<TContext>
    where TContext : DefaultMySqlContext
{
    /// <summary>
    ///     Constructs <see cref="DefaultMySqlCredentialStorage{TContext}" />.
    /// </summary>
    /// <param name="timeProvider">Current time provider.</param>
    /// <exception cref="ArgumentNullException">Any of the parameters is <see langword="null" /></exception>
    public DefaultMySqlCredentialStorage(ITimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);
        TimeProvider = timeProvider;
    }

    /// <summary>
    ///     Current time provider.
    /// </summary>
    protected ITimeProvider TimeProvider { get; }

    /// <inheritdoc />
    public virtual async Task<PublicKeyCredentialDescriptor[]> FindDescriptorsAsync(
        TContext context,
        string rpId,
        byte[] userHandle,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();
        var dbPublicKeysEnumerable = await context.Connection.QueryAsync<MySqlPublicKeyCredentialDescriptor>(new(@"
SELECT `Type`, `CredentialId`, `Transports`, `CreatedAtUnixTime`
FROM `CredentialRecords`
WHERE `UserHandle` = @userHandle AND `RpId` = @rpId;",
            new
            {
                rpId,
                userHandle
            },
            context.Transaction,
            cancellationToken: cancellationToken));

        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (dbPublicKeysEnumerable is null)
        {
            return Array.Empty<PublicKeyCredentialDescriptor>();
        }

        var dbPublicKeys = dbPublicKeysEnumerable
            .OrderByDescending(x => x.CreatedAtUnixTime)
            .ToList();
        var result = new PublicKeyCredentialDescriptor[dbPublicKeys.Count];
        for (var i = 0; i < dbPublicKeys.Count; i++)
        {
            if (!dbPublicKeys[i].TryToPublicKeyCredentialDescriptor(out var descriptor))
            {
                throw new InvalidOperationException($"Failed to convert data retrieved from the database into {nameof(PublicKeyCredentialDescriptor)}");
            }

            result[i] = descriptor;
        }

        return result;
    }

    /// <inheritdoc />
    public virtual async Task<UserCredentialRecord?> FindExistingCredentialForAuthenticationAsync(
        TContext context,
        string rpId,
        byte[] userHandle,
        byte[] credentialId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        var exisingId = await context.Connection.QuerySingleOrDefaultAsync<byte[]?>(new(@"
SELECT `Id`
FROM `CredentialRecords`
WHERE `UserHandle` = @userHandle AND `CredentialId` = @credentialId AND `RpId` = @rpId;",
            new
            {
                rpId,
                userHandle,
                credentialId
            },
            context.Transaction,
            cancellationToken: cancellationToken)
        );
        if (exisingId is null)
        {
            return null;
        }

        var model = await context.Connection.QuerySingleOrDefaultAsync<MySqlUserCredentialRecord?>(new(@"
SELECT
    `Id`,
    `RpId`,
    `UserHandle`,
    `CredentialId`,
    `Type`,
    `Kty`,
    `Alg`,
    `Ec2Crv`,
    `Ec2X`,
    `Ec2Y`,
    `RsaModulusN`,
    `RsaExponentE`,
    `OkpCrv`,
    `OkpX`,
    `SignCount`,
    `Transports`,
    `UvInitialized`,
    `BackupEligible`,
    `BackupState`,
    `AttestationObject`,
    `AttestationClientDataJson`,
    `Description`,
    `CreatedAtUnixTime`,
    `UpdatedAtUnixTime`
FROM `CredentialRecords`
WHERE `Id` = @id
FOR UPDATE;",
            new
            {
                id = exisingId
            },
            context.Transaction,
            cancellationToken: cancellationToken)
        );
        if (model is null)
        {
            return null;
        }

        if (!model.TryToUserCredentialRecord(out var result))
        {
            throw new InvalidOperationException($"Failed to convert data retrieved from the database into {nameof(UserCredentialRecord)}");
        }

        return result;
    }

    /// <inheritdoc />
    public virtual async Task<bool> SaveIfNotRegisteredForOtherUserAsync(
        TContext context,
        UserCredentialRecord credential,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(credential);
        cancellationToken.ThrowIfCancellationRequested();
        var existingCount = await context.Connection.ExecuteScalarAsync<long>(new(
            @"
SELECT COUNT(`CredentialId`)
FROM `CredentialRecords`
WHERE `CredentialId` = @credentialId AND `RpId` = @rpId;",
            new
            {
                rpId = credential.RpId,
                credentialId = credential.CredentialRecord.Id
            },
            context.Transaction,
            cancellationToken: cancellationToken
        ));

        if (existingCount > 0)
        {
            return false;
        }

        var id = UuidVersion7Generator.Generate();
        var createdAt = TimeProvider.GetPreciseUtcDateTime();
        var updatedAt = createdAt;
        var insert = MySqlUserCredentialRecord.Create(credential, id, createdAt, updatedAt);
        var rowsInserted = await context.Connection.ExecuteAsync(new(@"
INSERT INTO `CredentialRecords`
(
    `Id`,
    `RpId`,
    `UserHandle`,
    `CredentialId`,
    `Type`,
    `Kty`,
    `Alg`,
    `Ec2Crv`,
    `Ec2X`,
    `Ec2Y`,
    `RsaModulusN`,
    `RsaExponentE`,
    `OkpCrv`,
    `OkpX`,
    `SignCount`,
    `Transports`,
    `UvInitialized`,
    `BackupEligible`,
    `BackupState`,
    `AttestationObject`,
    `AttestationClientDataJson`,
    `Description`,
    `CreatedAtUnixTime`,
    `UpdatedAtUnixTime`
)
VALUES
(
     @id,
     @rpId,
     @userHandle,
     @credentialId,
     @type,
     @kty,
     @alg,
     @ec2Crv,
     @ec2X,
     @ec2Y,
     @rsaModulusN,
     @rsaExponentE,
     @okpCrv,
     @okpX,
     @signCount,
     @transports,
     @uvInitialized,
     @backupEligible,
     @backupState,
     @attestationObject,
     @attestationClientDataJson,
     @description,
     @createdAtUnixTime,
     @updatedAtUnixTime
);",
            new
            {
                id = insert.Id,
                rpId = insert.RpId,
                userHandle = insert.UserHandle,
                credentialId = insert.CredentialId,
                type = insert.Type,
                kty = insert.Kty,
                alg = insert.Alg,
                ec2Crv = insert.Ec2Crv,
                ec2X = insert.Ec2X,
                ec2Y = insert.Ec2Y,
                rsaModulusN = insert.RsaModulusN,
                rsaExponentE = insert.RsaExponentE,
                okpCrv = insert.OkpCrv,
                okpX = insert.OkpX,
                signCount = insert.SignCount,
                transports = insert.Transports,
                uvInitialized = insert.UvInitialized,
                backupEligible = insert.BackupEligible,
                backupState = insert.BackupState,
                attestationObject = insert.AttestationObject,
                attestationClientDataJson = insert.AttestationClientDataJson,
                description = insert.Description,
                createdAtUnixTime = insert.CreatedAtUnixTime,
                updatedAtUnixTime = insert.UpdatedAtUnixTime
            },
            context.Transaction,
            cancellationToken: cancellationToken
        ));

        return rowsInserted > 0;
    }

    /// <inheritdoc />
    public virtual async Task<bool> UpdateCredentialAsync(
        TContext context,
        UserCredentialRecord credential,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(credential);
        cancellationToken.ThrowIfCancellationRequested();
        var recordIdToUpdate = await context.Connection.QuerySingleOrDefaultAsync<byte[]?>(new(
            @"
SELECT `Id`
FROM `CredentialRecords`
WHERE `UserHandle` = @userHandle AND `CredentialId` = @credentialId AND `RpId` = @rpId;",
            new
            {
                rpId = credential.RpId,
                userHandle = credential.UserHandle,
                credentialId = credential.CredentialRecord.Id
            },
            context.Transaction,
            cancellationToken: cancellationToken
        ));

        if (recordIdToUpdate is null)
        {
            return false;
        }

        var updatedAt = TimeProvider.GetPreciseUtcDateTime();
        // We do not use CreatedAt for updating, so we pass default.
        var updated = MySqlUserCredentialRecord.Create(credential, recordIdToUpdate, default, updatedAt);
        var rowsUpdated = await context.Connection.ExecuteAsync(new(@"
UPDATE `CredentialRecords`
SET
    `Type` = @type,
    `Kty` = @kty,
    `Alg` = @alg,
    `Ec2Crv` = @ec2Crv,
    `Ec2X` = @ec2X,
    `Ec2Y` = @ec2Y,
    `RsaModulusN` = @rsaModulusN,
    `RsaExponentE` = @rsaExponentE,
    `OkpCrv` = @okpCrv,
    `OkpX` = @okpX,
    `SignCount` = @signCount,
    `Transports` = @transports,
    `UvInitialized` = @uvInitialized,
    `BackupEligible` = @backupEligible,
    `BackupState` = @backupState,
    `AttestationObject` = @attestationObject,
    `AttestationClientDataJson` = @attestationClientDataJson,
    `Description` = @description,
    `UpdatedAtUnixTime` = @updatedAtUnixTime
WHERE `Id` = @id;",
            new
            {
                id = updated.Id,
                type = updated.Type,
                kty = updated.Kty,
                alg = updated.Alg,
                ec2Crv = updated.Ec2Crv,
                ec2X = updated.Ec2X,
                ec2Y = updated.Ec2Y,
                rsaModulusN = updated.RsaModulusN,
                rsaExponentE = updated.RsaExponentE,
                okpCrv = updated.OkpCrv,
                okpX = updated.OkpX,
                signCount = updated.SignCount,
                transports = updated.Transports,
                uvInitialized = updated.UvInitialized,
                backupEligible = updated.BackupEligible,
                backupState = updated.BackupState,
                attestationObject = updated.AttestationObject,
                attestationClientDataJson = updated.AttestationClientDataJson,
                description = updated.Description,
                updatedAtUnixTime = updated.UpdatedAtUnixTime
            },
            context.Transaction,
            cancellationToken: cancellationToken
        ));

        return rowsUpdated > 0;
    }
}
