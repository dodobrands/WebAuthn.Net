using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Dapper;
using WebAuthn.Net.Models.Protocol;
using WebAuthn.Net.Services.Providers;
using WebAuthn.Net.Storage.Credential;
using WebAuthn.Net.Storage.Credential.Models;
using WebAuthn.Net.Storage.PostgreSql.Models;
using WebAuthn.Net.Storage.PostgreSql.Services.Static;
using WebAuthn.Net.Storage.PostgreSql.Storage.Models;

namespace WebAuthn.Net.Storage.PostgreSql.Storage;

public class DefaultPostgreSqlCredentialStorage<TContext> : ICredentialStorage<TContext>
    where TContext : DefaultPostgreSqlContext
{
    public DefaultPostgreSqlCredentialStorage(ITimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);
        TimeProvider = timeProvider;
    }

    protected ITimeProvider TimeProvider { get; }

    public virtual async Task<PublicKeyCredentialDescriptor[]> FindDescriptorsAsync(
        TContext context,
        string rpId,
        byte[] userHandle,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();
        var dbPublicKeysEnumerable = await context.Connection.QueryAsync<PostgreSqlPublicKeyCredentialDescriptor>(new(@"
SELECT ""Type"", ""CredentialId"", ""Transports"", ""CreatedAtUnixTime"" FROM ""CredentialRecords""
WHERE ""RpId"" = @rpId AND ""UserHandle"" = @userHandle;",
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
            if (!dbPublicKeys[i].TryMapToResult(out var descriptor))
            {
                throw new InvalidOperationException($"Failed to convert data retrieved from the database into {nameof(PublicKeyCredentialDescriptor)}");
            }

            result[i] = descriptor;
        }

        return result;
    }

    public virtual async Task<UserCredentialRecord?> FindExistingCredentialForAuthenticationAsync(
        TContext context,
        string rpId,
        byte[] userHandle,
        byte[] credentialId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();
        var model = await context.Connection.QuerySingleOrDefaultAsync<PostgreSqlUserCredentialRecord>(new(@"
SELECT
    ""Id"",
    ""RpId"",
    ""UserHandle"",
    ""CredentialId"",
    ""Type"",
    ""Kty"",
    ""Alg"",
    ""EcdsaCrv"",
    ""EcdsaX"",
    ""EcdsaY"",
    ""RsaModulusN"",
    ""RsaExponentE"",
    ""SignCount"",
    ""Transports"",
    ""UvInitialized"",
    ""BackupEligible"",
    ""BackupState"",
    ""AttestationObject"",
    ""AttestationClientDataJson"",
    ""CreatedAtUnixTime""
FROM ""CredentialRecords""
WHERE ""RpId"" = @rpId AND ""UserHandle"" = @userHandles AND ""CredentialId"" = @credentialId
FOR UPDATE;",
            new
            {
                rpId,
                userHandle,
                credentialId
            },
            context.Transaction,
            cancellationToken: cancellationToken)
        );
        if (model is null)
        {
            return null;
        }

        if (!model.TryMapToResult(out var result))
        {
            throw new InvalidOperationException($"Failed to convert data retrieved from the database into {nameof(UserCredentialRecord)}");
        }

        return result;
    }

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
SELECT COUNT(""Id"") FROM ""CredentialRecords""
WHERE
    ""RpId"" = @rpId
    AND ""UserHandle"" = @userHandles
    AND ""CredentialId"" = @credentialId;",
            new
            {
                rpId = credential.RpId,
                userHandle = credential.UserHandle,
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
        var timestamp = TimeProvider.GetPreciseUtcDateTime().ToUnixTimeSeconds();
        var rowsAffected = await context.Connection.ExecuteAsync(new(@"
INSERT INTO ""CredentialRecords""
(
    ""Id"",
    ""RpId"",
    ""UserHandle"",
    ""CredentialId"",
    ""Type"",
    ""Kty"",
    ""Alg"",
    ""EcdsaCrv"",
    ""EcdsaX"",
    ""EcdsaY"",
    ""RsaModulusN"",
    ""RsaExponentE"",
    ""SignCount"",
    ""Transports"",
    ""UvInitialized"",
    ""BackupEligible"",
    ""BackupState"",
    ""AttestationObject"",
    ""AttestationClientDataJson"",
    ""CreatedAtUnixTime""
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
     @ecdsaCrv,
     @ecdsaX,
     @ecdsaY,
     @rsaModulusN,
     @rsaExponentE,
     @signCount,
     @transports,
     @uvInitialized,
     @backupEligible,
     @backupState,
     @attestationObject,
     @attestationClientDataJson,
     @createdAtUnixTime
);",
            new
            {
                id,
                rpId = credential.RpId,
                userHandle = credential.UserHandle,
                credentialId = credential.CredentialRecord.Id,
                type = credential.CredentialRecord.Type,
                kty = credential.CredentialRecord.PublicKey.Kty,
                alg = credential.CredentialRecord.PublicKey.Alg,
                ecdsaCrv = credential.CredentialRecord.PublicKey.Ec2?.Crv,
                ecdsaX = credential.CredentialRecord.PublicKey.Ec2?.X,
                ecdsaY = credential.CredentialRecord.PublicKey.Ec2?.Y,
                rsaModulusN = credential.CredentialRecord.PublicKey.Rsa?.ModulusN,
                rsaExponentE = credential.CredentialRecord.PublicKey.Rsa?.ExponentE,
                signCount = credential.CredentialRecord.SignCount,
                transports = credential.CredentialRecord.Transports,
                uvInitialized = credential.CredentialRecord.UvInitialized,
                backupEligible = credential.CredentialRecord.BackupEligible,
                backupState = credential.CredentialRecord.BackupState,
                attestationObject = credential.CredentialRecord.AttestationObject,
                attestationClientDataJson = credential.CredentialRecord.AttestationClientDataJSON,
                createdAtUnixTime = timestamp
            },
            context.Transaction,
            cancellationToken: cancellationToken
        ));

        return rowsAffected > 0;
    }

    public virtual async Task<bool> UpdateCredentialAsync(
        TContext context,
        UserCredentialRecord credential,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(credential);
        cancellationToken.ThrowIfCancellationRequested();
        var rowsAffected = await context.Connection.ExecuteAsync(new(@"
UPDATE ""CredentialRecords""
SET
    ""Type"" = @type,
    ""Kty"" = @kty,
    ""Alg"" = @alg,
    ""EcdsaCrv"" = @ecdsaCrv,
    ""EcdsaX"" = @ecdsaX,
    ""EcdsaY"" = @ecdsaY,
    ""RsaModulusN"" = @rsaModulusN,
    ""RsaExponentE"" = @rsaExponentE,
    ""SignCount"" = @signCount,
    ""Transports"" = @transports,
    ""UvInitialized"" = @uvInitialized,
    ""BackupEligible"" = @backupEligible,
    ""BackupState"" = @backupState,
    ""AttestationObject"" = @attestationObject,
    ""AttestationClientDataJson"" = @attestationClientDataJson
WHERE
    ""RpId"" = @rpId
    AND ""UserHandle"" = @userHandle
    AND ""CredentialId"" = @credentialId;",
            new
            {
                type = credential.CredentialRecord.Type,
                kty = credential.CredentialRecord.PublicKey.Kty,
                alg = credential.CredentialRecord.PublicKey.Alg,
                ecdsaCrv = credential.CredentialRecord.PublicKey.Ec2?.Crv,
                ecdsaX = credential.CredentialRecord.PublicKey.Ec2?.X,
                ecdsaY = credential.CredentialRecord.PublicKey.Ec2?.Y,
                rsaModulusN = credential.CredentialRecord.PublicKey.Rsa?.ModulusN,
                rsaExponentE = credential.CredentialRecord.PublicKey.Rsa?.ExponentE,
                signCount = credential.CredentialRecord.SignCount,
                transports = credential.CredentialRecord.Transports,
                uvInitialized = credential.CredentialRecord.UvInitialized,
                backupEligible = credential.CredentialRecord.BackupEligible,
                backupState = credential.CredentialRecord.BackupState,
                attestationObject = credential.CredentialRecord.AttestationObject,
                attestationClientDataJson = credential.CredentialRecord.AttestationClientDataJSON,
                rpId = credential.RpId,
                userHandle = credential.UserHandle,
                credentialId = credential.CredentialRecord.Id
            },
            context.Transaction,
            cancellationToken: cancellationToken
        ));

        return rowsAffected > 0;
    }
}
