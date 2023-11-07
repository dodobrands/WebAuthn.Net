using System;
using System.Text.Json;

namespace WebAuthn.Net.Storage.Credential.Models;

public class UserCredentialRecord
{
    public UserCredentialRecord(byte[] userHandle, string rpId, CredentialRecord credentialRecord)
    {
        UserHandle = userHandle;
        RpId = rpId;
        CredentialRecord = credentialRecord;
    }

    public byte[] UserHandle { get; }

    public string RpId { get; }

    public CredentialRecord CredentialRecord { get; }

    public bool ContainsCredentialThatBelongsTo(string rpId, byte[] userHandle, byte[] credentialId)
    {
        return rpId == RpId
               && userHandle.AsSpan().SequenceEqual(UserHandle.AsSpan())
               && credentialId.AsSpan().SequenceEqual(CredentialRecord.Id.AsSpan());
    }

        public object AsInsertQueryParams(DateTimeOffset createdAt, byte[] id)
    {
        var transportsJson = JsonSerializer.Serialize(CredentialRecord.Transports);
        return new
        {
            id,
            rpId = RpId,
            userHandle = UserHandle,
            credentialId = CredentialRecord.Id,
            type = CredentialRecord.Type,
            kty = CredentialRecord.PublicKey.Kty,
            alg = CredentialRecord.PublicKey.Alg,
            ecdsaCrv = CredentialRecord.PublicKey.Ec2?.Crv,
            ecdsaX = CredentialRecord.PublicKey.Ec2?.X,
            ecdsaY = CredentialRecord.PublicKey.Ec2?.Y,
            rsaModulusN = CredentialRecord.PublicKey.Rsa?.ModulusN,
            rsaExponentE = CredentialRecord.PublicKey.Rsa?.ExponentE,
            signCount = CredentialRecord.SignCount,
            transports = transportsJson,
            uvInitialized = CredentialRecord.UvInitialized,
            backupEligible = CredentialRecord.BackupEligible,
            backupState = CredentialRecord.BackupState,
            attestationObject = CredentialRecord.AttestationObject,
            attestationClientDataJson = CredentialRecord.AttestationClientDataJSON,
            createdAtUnixTime = createdAt.ToUnixTimeMilliseconds()
        };
    }

    public object AsUpdateQueryParams(byte[] id)
    {
        var transportsJson = JsonSerializer.Serialize(CredentialRecord.Transports);
        return new
        {
            id,
            type = CredentialRecord.Type,
            kty = CredentialRecord.PublicKey.Kty,
            alg = CredentialRecord.PublicKey.Alg,
            ecdsaCrv = CredentialRecord.PublicKey.Ec2?.Crv,
            ecdsaX = CredentialRecord.PublicKey.Ec2?.X,
            ecdsaY = CredentialRecord.PublicKey.Ec2?.Y,
            rsaModulusN = CredentialRecord.PublicKey.Rsa?.ModulusN,
            rsaExponentE = CredentialRecord.PublicKey.Rsa?.ExponentE,
            signCount = CredentialRecord.SignCount,
            transports = transportsJson,
            uvInitialized = CredentialRecord.UvInitialized,
            backupEligible = CredentialRecord.BackupEligible,
            backupState = CredentialRecord.BackupState,
            attestationObject = CredentialRecord.AttestationObject,
            attestationClientDataJson = CredentialRecord.AttestationClientDataJSON,
        };
    }
}
