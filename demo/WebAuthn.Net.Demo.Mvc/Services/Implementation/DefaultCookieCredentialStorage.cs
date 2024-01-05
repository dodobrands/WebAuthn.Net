using System.ComponentModel.DataAnnotations;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.WebUtilities;
using WebAuthn.Net.Demo.Mvc.Constants;
using WebAuthn.Net.Demo.Mvc.Services.Abstractions.CookieStore;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Models.Protocol;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.Providers;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums.EC2;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums.OKP;
using WebAuthn.Net.Storage.Credential;
using WebAuthn.Net.Storage.Credential.Models;

namespace WebAuthn.Net.Demo.Mvc.Services.Implementation;

public class DefaultCookieCredentialStorage<TContext>
    : AbstractProtectedCookieStore, ICredentialStorage<TContext>
    where TContext : class, IWebAuthnContext
{
    private const string DataProtectionPurpose = "WebAuthn.Net.Demo.CredentialStorage";
    private const int ItemsToPreserve = 5;

    public DefaultCookieCredentialStorage(
        IDataProtectionProvider provider,
        ITimeProvider timeProvider) : base(provider, DataProtectionPurpose, CookieConstants.Credentials)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);
        TimeProvider = timeProvider;
    }

    private ITimeProvider TimeProvider { get; }

    public Task<PublicKeyCredentialDescriptor[]> FindDescriptorsAsync(
        TContext context,
        string rpId,
        byte[] userHandle,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();
        var existingItems = Read(context.HttpContext);
        var resultAccumulator = new List<PublicKeyCredentialDescriptor>(existingItems.Length);
        foreach (var existingItem in existingItems)
        {
            if (!existingItem.TryMapToDescriptor(out var descriptor)
                || !existingItem.TryMapToUserCredentialRecord(out var credentialRecord))
            {
                throw new InvalidOperationException("Can't get descriptor");
            }

            if (credentialRecord.RpId == rpId && credentialRecord.UserHandle.AsSpan().SequenceEqual(userHandle))
            {
                resultAccumulator.Add(descriptor);
            }
        }

        return Task.FromResult(resultAccumulator.ToArray());
    }

    public Task<UserCredentialRecord?> FindExistingCredentialForAuthenticationAsync(
        TContext context,
        string rpId,
        byte[] userHandle,
        byte[] credentialId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();
        var existingItems = Read(context.HttpContext);
        var resultAccumulator = new List<UserCredentialRecord>(existingItems.Length);
        foreach (var existingItem in existingItems)
        {
            if (!existingItem.TryMapToUserCredentialRecord(out var credentialRecord))
            {
                throw new InvalidOperationException("Can't get user credential record");
            }

            resultAccumulator.Add(credentialRecord);
        }

        var foundCredentialRecord = resultAccumulator.FirstOrDefault(x =>
            x.RpId == rpId
            && x.UserHandle.AsSpan().SequenceEqual(userHandle)
            && x.CredentialRecord.Id.AsSpan().SequenceEqual(credentialId));
        return Task.FromResult(foundCredentialRecord);
    }

    public Task<bool> SaveIfNotRegisteredForOtherUserAsync(
        TContext context,
        UserCredentialRecord credential,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();
        var existingItems = Read(context.HttpContext);
        var resultAccumulator = new List<UserCredentialRecord>(existingItems.Length);
        foreach (var existingItem in existingItems)
        {
            if (!existingItem.TryMapToUserCredentialRecord(out var credentialRecord))
            {
                throw new InvalidOperationException("Can't get user credential record");
            }

            resultAccumulator.Add(credentialRecord);
        }

        if (resultAccumulator.Any(x =>
                x.RpId == credential.RpId
                && x.CredentialRecord.Id.AsSpan().SequenceEqual(credential.CredentialRecord.Id)))
        {
            return Task.FromResult(false);
        }

        var createdAt = TimeProvider.GetPreciseUtcDateTime();
        var updatedAt = createdAt;
        var newCredential = JsonUserCredentialRecord.Create(credential, createdAt, updatedAt);
        var itemsToPreserve = BuildNewItemsToPreserve(newCredential, existingItems);
        Write(context.HttpContext, itemsToPreserve);
        return Task.FromResult(true);
    }

    public Task<bool> UpdateCredentialAsync(
        TContext context,
        UserCredentialRecord credential,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();
        var existingItems = Read(context.HttpContext);
        var resultAccumulator = new List<CombinedCredentialRecord>(existingItems.Length);
        foreach (var existingItem in existingItems)
        {
            if (!existingItem.TryMapToUserCredentialRecord(out var credentialRecord))
            {
                throw new InvalidOperationException("Can't get user credential record");
            }

            resultAccumulator.Add(new(credentialRecord, existingItem));
        }

        var itemToUpdate = resultAccumulator.FirstOrDefault(x =>
            x.User.RpId == credential.RpId
            && x.User.UserHandle.AsSpan().SequenceEqual(credential.UserHandle)
            && x.User.CredentialRecord.Id.AsSpan().SequenceEqual(credential.CredentialRecord.Id));
        if (itemToUpdate is null)
        {
            return Task.FromResult(false);
        }

        resultAccumulator.Remove(itemToUpdate);
        var createdAt = DateTimeOffset.FromUnixTimeSeconds(itemToUpdate.Json.CreatedAtUnixTime);
        var updatedAt = TimeProvider.GetPreciseUtcDateTime();
        var updatedItem = JsonUserCredentialRecord.Create(credential, createdAt, updatedAt);
        var allRemainItems = resultAccumulator.Select(x => x.Json).ToArray();
        var itemsToPreserve = BuildNewItemsToPreserve(updatedItem, allRemainItems);
        Write(context.HttpContext, itemsToPreserve);
        return Task.FromResult(true);
    }

    private JsonUserCredentialRecord[] Read(HttpContext httpContext)
    {
        if (!TryRead(httpContext, out var payload))
        {
            return Array.Empty<JsonUserCredentialRecord>();
        }

        var credRecords = JsonSerializer.Deserialize<JsonUserCredentialRecord[]>(payload);
        if (credRecords is null)
        {
            return Array.Empty<JsonUserCredentialRecord>();
        }

        var result = credRecords
            .OrderByDescending(x => x.UpdatedAtUnixTime)
            .ToArray();

        return result;
    }

    private void Write(HttpContext httpContext, JsonUserCredentialRecord[] itemsToWrite)
    {
        var dataToWrite = JsonSerializer.SerializeToUtf8Bytes(itemsToWrite);
        Save(httpContext, dataToWrite);
    }

    private static JsonUserCredentialRecord[] BuildNewItemsToPreserve(
        JsonUserCredentialRecord newItem,
        JsonUserCredentialRecord[] existingItems)
    {
        var resultAccumulator = new List<JsonUserCredentialRecord>
        {
            newItem
        };
        foreach (var existingItem in existingItems)
        {
            // do not overwrite the newly added item with the old value
            // the new one is prioritized
            if (existingItem.UserHandle == newItem.UserHandle
                && existingItem.RpId == newItem.RpId
                && existingItem.CredentialId == newItem.CredentialId)
            {
                continue;
            }

            resultAccumulator.Add(existingItem);
        }

        var itemsToPreserve = resultAccumulator
            .OrderByDescending(x => x.UpdatedAtUnixTime)
            .Take(ItemsToPreserve)
            .ToArray();
        return itemsToPreserve;
    }

    private sealed class CombinedCredentialRecord(UserCredentialRecord user, JsonUserCredentialRecord json)
    {
        public UserCredentialRecord User { get; } = user;
        public JsonUserCredentialRecord Json { get; } = json;
    }

    [method: JsonConstructor]
    private sealed class JsonUserCredentialRecord(
        string rpId,
        string userHandle,
        string credentialId,
        int type,
        int kty,
        int alg,
        int? ec2Crv,
        string? ec2X,
        string? ec2Y,
        string? rsaModulusN,
        string? rsaExponentE,
        int? okpCrv,
        string? okpX,
        uint signCount,
        int[] transports,
        bool uvInitialized,
        bool backupEligible,
        bool backupState,
        string? attestationObject,
        string? attestationClientDataJson,
        string? description,
        long createdAtUnixTime,
        long updatedAtUnixTime)
    {
        [JsonPropertyName("rpid")]
        public string RpId { get; } = rpId;

        [JsonPropertyName("usr")]
        public string UserHandle { get; } = userHandle;

        [JsonPropertyName("cred")]
        public string CredentialId { get; } = credentialId;

        [JsonPropertyName("typ")]
        public int Type { get; } = type;

        [JsonPropertyName("kty")]
        public int Kty { get; } = kty;

        [JsonPropertyName("alg")]
        public int Alg { get; } = alg;

        [JsonPropertyName("ec")]
        public int? Ec2Crv { get; } = ec2Crv;

        [JsonPropertyName("ex")]
        [MaxLength(256)]
        public string? Ec2X { get; } = ec2X;

        [JsonPropertyName("ey")]
        [MaxLength(256)]
        public string? Ec2Y { get; } = ec2Y;

        [JsonPropertyName("rm")]
        [MaxLength(8192 / 8)]
        public string? RsaModulusN { get; } = rsaModulusN;

        [JsonPropertyName("re")]
        [MaxLength(256 / 8)]
        public string? RsaExponentE { get; } = rsaExponentE;

        [JsonPropertyName("oc")]
        public int? OkpCrv { get; } = okpCrv;

        [JsonPropertyName("ox")]
        [MaxLength(32)]
        public string? OkpX { get; } = okpX;

        [JsonPropertyName("sign")]
        public uint SignCount { get; } = signCount;

        [JsonPropertyName("tran")]
        public int[] Transports { get; } = transports;

        [JsonPropertyName("uv")]
        public bool UvInitialized { get; } = uvInitialized;

        [JsonPropertyName("be")]
        public bool BackupEligible { get; } = backupEligible;

        [JsonPropertyName("bs")]
        public bool BackupState { get; } = backupState;

        [JsonPropertyName("atto")]
        public string? AttestationObject { get; } = attestationObject;

        [JsonPropertyName("attcd")]
        public string? AttestationClientDataJson { get; } = attestationClientDataJson;

        [JsonPropertyName("desc")]
        [MaxLength(200)]
        public string? Description { get; } = description;

        [JsonPropertyName("cr")]
        public long CreatedAtUnixTime { get; } = createdAtUnixTime;

        [JsonPropertyName("upd")]
        public long UpdatedAtUnixTime { get; } = updatedAtUnixTime;

        public static JsonUserCredentialRecord Create(UserCredentialRecord record, DateTimeOffset createdAt, DateTimeOffset updatedAt)
        {
            ArgumentNullException.ThrowIfNull(record);
            var rpId = record.RpId;
            var userHandle = WebEncoders.Base64UrlEncode(record.UserHandle);
            var credentialId = WebEncoders.Base64UrlEncode(record.CredentialRecord.Id);
            var type = (int) record.CredentialRecord.Type;
            var kty = (int) record.CredentialRecord.PublicKey.Kty;
            var alg = (int) record.CredentialRecord.PublicKey.Alg;
            var ec2Crv = (int?) record.CredentialRecord.PublicKey.Ec2?.Crv;
            var ec2X = record.CredentialRecord.PublicKey.Ec2?.X is not null
                ? WebEncoders.Base64UrlEncode(record.CredentialRecord.PublicKey.Ec2.X)
                : null;
            var ec2Y = record.CredentialRecord.PublicKey.Ec2?.Y is not null
                ? WebEncoders.Base64UrlEncode(record.CredentialRecord.PublicKey.Ec2.Y)
                : null;
            var rsaModulusN = record.CredentialRecord.PublicKey.Rsa?.ModulusN is not null
                ? WebEncoders.Base64UrlEncode(record.CredentialRecord.PublicKey.Rsa.ModulusN)
                : null;
            var rsaExponentE = record.CredentialRecord.PublicKey.Rsa?.ExponentE is not null
                ? WebEncoders.Base64UrlEncode(record.CredentialRecord.PublicKey.Rsa.ExponentE)
                : null;

            var okpCrv = (int?) record.CredentialRecord.PublicKey.Okp?.Crv;
            var okpX = record.CredentialRecord.PublicKey.Okp?.X is not null
                ? WebEncoders.Base64UrlEncode(record.CredentialRecord.PublicKey.Okp.X)
                : null;
            var signCount = record.CredentialRecord.SignCount;
            var transports = record.CredentialRecord.Transports.Select(x => (int) x).ToArray();
            var uvInitialized = record.CredentialRecord.UvInitialized;
            var backupEligible = record.CredentialRecord.BackupEligible;
            var backupState = record.CredentialRecord.BackupState;
            var attestationObject = record.CredentialRecord.AttestationObject is not null
                ? WebEncoders.Base64UrlEncode(record.CredentialRecord.AttestationObject)
                : null;
            var attestationClientDataJson = record.CredentialRecord.AttestationClientDataJSON is not null
                ? WebEncoders.Base64UrlEncode(record.CredentialRecord.AttestationClientDataJSON)
                : null;
            var description = record.Description;
            var createdAtUnixTime = createdAt.ToUnixTimeSeconds();
            var updatedAtUnixTime = updatedAt.ToUnixTimeSeconds();
            var result = new JsonUserCredentialRecord(
                rpId,
                userHandle,
                credentialId,
                type,
                kty,
                alg,
                ec2Crv,
                ec2X,
                ec2Y,
                rsaModulusN,
                rsaExponentE,
                okpCrv,
                okpX,
                signCount,
                transports,
                uvInitialized,
                backupEligible,
                backupState,
                attestationObject,
                attestationClientDataJson,
                description,
                createdAtUnixTime,
                updatedAtUnixTime);
            return result;
        }

        [return: NotNullIfNotNull("src")]
        private static T[]? CopyArray<T>(T[]? src)
        {
            if (src is null)
            {
                return null;
            }

            if (src.Length == 0)
            {
                return Array.Empty<T>();
            }

            var result = new T[src.Length];
            Array.Copy(src, result, src.Length);
            return result;
        }

        public bool TryMapToDescriptor([NotNullWhen(true)] out PublicKeyCredentialDescriptor? result)
        {
            result = null;
            var publicKeyCredentialType = (PublicKeyCredentialType) Type;
            if (!Enum.IsDefined(publicKeyCredentialType))
            {
                return false;
            }

            var credentialId = WebEncoders.Base64UrlDecode(CredentialId);
            var authenticatorTransports = Transports
                .Select(x => (AuthenticatorTransport) x)
                .ToArray();
            foreach (var authenticatorTransport in authenticatorTransports)
            {
                if (!Enum.IsDefined(authenticatorTransport))
                {
                    return false;
                }
            }

            result = new(
                publicKeyCredentialType,
                credentialId,
                authenticatorTransports);
            return true;
        }

        public bool TryMapToUserCredentialRecord([NotNullWhen(true)] out UserCredentialRecord? result)
        {
            result = null;
            var publicKeyCredentialType = (PublicKeyCredentialType) Type;
            if (!Enum.IsDefined(publicKeyCredentialType))
            {
                return false;
            }

            var coseKeyType = (CoseKeyType) Kty;
            if (!Enum.IsDefined(coseKeyType))
            {
                return false;
            }

            var coseAlgorithm = (CoseAlgorithm) Alg;
            if (!Enum.IsDefined(coseAlgorithm))
            {
                return false;
            }

            CredentialPublicKeyRsaParametersRecord? rsaKey = null;
            CredentialPublicKeyEc2ParametersRecord? ecKey = null;
            CredentialPublicKeyOkpParametersRecord? okpKey = null;

            switch (coseKeyType)
            {
                case CoseKeyType.EC2:
                    {
                        if (!Ec2Crv.HasValue)
                        {
                            return false;
                        }

                        var ec2Curve = (CoseEc2EllipticCurve) Ec2Crv.Value;
                        if (!Enum.IsDefined(ec2Curve) || Ec2X is null || Ec2Y is null)
                        {
                            return false;
                        }

                        ecKey = new(ec2Curve, WebEncoders.Base64UrlDecode(Ec2X), WebEncoders.Base64UrlDecode(Ec2Y));
                        break;
                    }
                case CoseKeyType.RSA:
                    {
                        if (RsaModulusN is null || RsaExponentE is null)
                        {
                            return false;
                        }

                        rsaKey = new(WebEncoders.Base64UrlDecode(RsaModulusN), WebEncoders.Base64UrlDecode(RsaExponentE));
                        break;
                    }
                case CoseKeyType.OKP:
                    {
                        if (!OkpCrv.HasValue)
                        {
                            return false;
                        }

                        var okpCurve = (CoseOkpEllipticCurve) OkpCrv.Value;
                        if (!Enum.IsDefined(okpCurve) || OkpX is null)
                        {
                            return false;
                        }

                        okpKey = new(okpCurve, WebEncoders.Base64UrlDecode(OkpX));
                        break;
                    }
                default:
                    return false;
            }

            var publicKey = new CredentialPublicKeyRecord(
                coseKeyType,
                coseAlgorithm,
                rsaKey,
                ecKey,
                okpKey);

            var authenticatorTransports = Transports
                .Select(x => (AuthenticatorTransport) x)
                .ToArray();
            foreach (var authenticatorTransport in authenticatorTransports)
            {
                if (!Enum.IsDefined(authenticatorTransport))
                {
                    return false;
                }
            }

            var attestationObject = AttestationObject is not null
                ? WebEncoders.Base64UrlDecode(AttestationObject)
                : null;
            var attestationClientDataJson = AttestationClientDataJson is not null
                ? WebEncoders.Base64UrlDecode(AttestationClientDataJson)
                : null;
            var credentialRecord = new CredentialRecord(
                publicKeyCredentialType,
                WebEncoders.Base64UrlDecode(CredentialId),
                publicKey,
                SignCount,
                authenticatorTransports,
                UvInitialized,
                BackupEligible,
                BackupState,
                attestationObject,
                attestationClientDataJson
            );
            var userHandle = WebEncoders.Base64UrlDecode(UserHandle);
            result = new(userHandle, RpId, Description, credentialRecord);
            return true;
        }
    }
}
