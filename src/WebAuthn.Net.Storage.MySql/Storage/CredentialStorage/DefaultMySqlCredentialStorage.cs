using System;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Dapper;
using WebAuthn.Net.Models.Protocol;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.Providers;
using WebAuthn.Net.Storage.Credential;
using WebAuthn.Net.Storage.Credential.Models;
using WebAuthn.Net.Storage.MySql.Models;
using WebAuthn.Net.Storage.MySql.Services.Static;

namespace WebAuthn.Net.Storage.MySql.Storage.CredentialStorage;

public static class MySqlCredentialStorageSql
{
    public const string FindDescriptors = @"
SELECT `Type`, `CredentialId`, `Transports`, `CreatedAtUnixTime` FROM `CredentialRecords`
WHERE `RpId` = @rpId AND `UserHandle` = @userHandle;
";

    public const string FindCredentials = @"
SELECT * FROM `CredentialRecords`
WHERE `RpId` = @rpId AND `UserHandle` = @userHandles AND `credentialId` = @credentialId;
";

    public const string SelectForUpdate = @"
    SELECT `Id` FROM `CredentialRecords`
    WHERE `RpId` = @rpId AND `UserHandle` = @userHandles AND `credentialId` = @credentialId
    FOR UPDATE;
";

    public const string InsertCredentialRecords = @"
    INSERT INTO `CredentialRecords`
    (
    `Id`,
    `RpId`,
    `UserHandle`,
    `CredentialId`,
    `Type`,
    `Kty`,
    `Alg`,
    `EcdsaCrv`,
    `EcdsaX`,
    `EcdsaY`,
    `RsaModulusN`,
    `RsaExponentE`,
    `SignCount`,
    `Transports`,
    `UvInitialized`,
    `BackupEligible`,
    `BackupState`,
    `AttestationObject`,
    `AttestationClientDataJson`,
    `CreatedAtUnixTime`
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
     );
";

    public const string UpdateCredentialRecords = @"
    UPDATE `CredentialRecords`
    SET
     `type` = @type,
     `kty` = @kty,
     `alg` = @alg,
     `ecdsaCrv` = @ecdsaCrv,
     `ecdsaX` = @ecdsaX,
     `ecdsaY` = @ecdsaY,
     `rsaModulusN` = @rsaModulusN,
     `rsaExponentE` = @rsaExponentE,
     `signCount` = @signCount,
     `transports` = @transports,
     `uvInitialized` = @uvInitialized,
     `backupEligible` = @backupEligible,
     `backupState` = @backupState,
     `attestationObject` = @attestationObject,
     `attestationClientDataJson` = @attestationClientDataJson
    WHERE Id = @id;
";
}

public class DefaultMySqlCredentialStorage<TContext> : ICredentialStorage<TContext>
    where TContext : DefaultMySqlContext
{
    protected ITimeProvider TimeProvider { get; }

    public DefaultMySqlCredentialStorage(ITimeProvider timeProvider)
    {
        TimeProvider = timeProvider;
    }


    public async Task<PublicKeyCredentialDescriptor[]?> FindDescriptorsAsync(
        TContext context,
        string rpId,
        byte[] userHandle,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();
        var queryParams = new
        {
            rpId,
            userHandle
        };
        var dbPublicKeys = await context.Connection.QueryAsync<MySqlPublicKeyCredentialDescriptor>(new(
                MySqlCredentialStorageSql.FindDescriptors,
                queryParams,
                context.Transaction,
                cancellationToken: cancellationToken
            )
        );

        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (dbPublicKeys is null)
        {
            return Array.Empty<PublicKeyCredentialDescriptor>();
        }

        return dbPublicKeys
            .OrderByDescending(x => x.CreatedAtUnixTime)
            .Select(x => x.ToResultModel())
            .ToArray();
    }


    public async Task<UserCredentialRecord?> FindCredentialAsync(
        TContext context,
        string rpId,
        byte[] userHandle,
        byte[] credentialId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        var queryParams = new
        {
            rpId,
            userHandle,
            credentialId
        };

        var model = await context.Connection.QuerySingleAsync<MySqlUserCredentialRecord>(new(
            MySqlCredentialStorageSql.FindCredentials,
            queryParams,
            context.Transaction,
            cancellationToken: cancellationToken)
        );

        return model.MapToRecord();
    }

    public async Task<bool> SaveIfNotRegisteredForOtherUserAsync(
        TContext context,
        UserCredentialRecord credential,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(credential);

        var queryParams = new
        {
            rpId = credential.RpId,
            userHandle = credential.UserHandle,
            credentialId = credential.CredentialRecord.Id
        };
        var idsBytes = await context.Connection.QueryFirstOrDefaultAsync<byte[]>(new(
            MySqlCredentialStorageSql.SelectForUpdate,
            queryParams,
            context.Transaction,
            cancellationToken: cancellationToken
            ));

        if (idsBytes is not null) return false;

        var id = UuidVersion7Generator.Generate();
        var timestamp = TimeProvider.GetPreciseUtcDateTime();
        var upsertQueryParams = credential.AsInsertQueryParams(timestamp, id);

        var affectedRows = await context.Connection.ExecuteAsync(new(
            MySqlCredentialStorageSql.InsertCredentialRecords,
            upsertQueryParams,
            context.Transaction,
            cancellationToken: cancellationToken
        ));

        return affectedRows > 0;
    }

    public async Task<bool> UpdateCredentialAsync(
        TContext context,
        UserCredentialRecord credential,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(credential);

        var queryParams = new
        {
            rpId = credential.RpId,
            userHandle = credential.UserHandle,
            credentialId = credential.CredentialRecord.Id
        };
        var idsBytes = await context.Connection.QueryFirstOrDefaultAsync<byte[]>(new(
            MySqlCredentialStorageSql.SelectForUpdate,
            queryParams,
            context.Transaction,
            cancellationToken: cancellationToken
        ));

        if (idsBytes is null) return false;

        var updateQueryParams = credential.AsUpdateQueryParams(idsBytes);
        var rowsAffected = await context.Connection.ExecuteAsync(new(
            MySqlCredentialStorageSql.UpdateCredentialRecords,
            updateQueryParams,
            context.Transaction,
            cancellationToken: cancellationToken
            ));

        return rowsAffected > 0;
    }

    [SuppressMessage("Design", "CA1812:Avoid uninstantiated internal classes")]
    private class MySqlPublicKeyCredentialDescriptor
    {
        public MySqlPublicKeyCredentialDescriptor(int type, byte[] credentialId, string transports, long createdAtUnixTime)
        {
            Type = type;
            CredentialId = credentialId;
            Transports = transports;
            CreatedAtUnixTime = createdAtUnixTime;
        }

        public int Type { get; }

        public byte[] CredentialId { get; }

        public string Transports { get; }

        public long CreatedAtUnixTime { get; }

        public PublicKeyCredentialDescriptor ToResultModel()
        {
            var type = (PublicKeyCredentialType) Type;
            var transports = Array.Empty<AuthenticatorTransport>();
            if (!string.IsNullOrEmpty(Transports))
            {
                var deserializedTransports = JsonSerializer.Deserialize<int[]>(Transports);
                if (deserializedTransports?.Length > 0)
                {
                    transports = deserializedTransports.Select(x => (AuthenticatorTransport) x).ToArray();
                }
            }

            return new(
                type,
                CredentialId,
                transports);
        }
    }
}
