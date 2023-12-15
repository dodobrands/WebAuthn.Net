using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Text.Json;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums.EC2;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums.OKP;
using WebAuthn.Net.Storage.Credential.Models;

namespace WebAuthn.Net.Storage.PostgreSql.Storage.Models;

public class PostgreSqlUserCredentialRecord
{
    [Required]
    public Guid Id { get; set; }

    [Required]
    [MaxLength(256)]
    public string RpId { get; set; } = null!;

    [Required]
    [MaxLength(128)]
    public byte[] UserHandle { get; set; } = null!;

    [Required]
    [MaxLength(1024)]
    public byte[] CredentialId { get; set; } = null!;

    public int Type { get; set; }

    public int Kty { get; set; }

    public int Alg { get; set; }

    public int? Ec2Crv { get; set; }

    [MaxLength(256)]
    public byte[]? Ec2X { get; set; }

    [MaxLength(256)]
    public byte[]? Ec2Y { get; set; }

    [MaxLength(8192 / 8)]
    public byte[]? RsaModulusN { get; set; }

    // NIST SP 800-56B Rev. 2
    // https://doi.org/10.6028/NIST.SP.800-56Br2
    // 6.2 Criteria for RSA Key Pairs for Key Establishment
    // 6.2.1 Definition of a Key Pair
    // The public exponent e shall be an odd integer that is selected prior to the generation of p and q such that:
    // 65,537 ≤ e < 2^256
    [MaxLength(256 / 8)]
    public byte[]? RsaExponentE { get; set; }

    public int? OkpCrv { get; set; }

    [MaxLength(32)]
    public byte[]? OkpX { get; set; }

    public long SignCount { get; set; }

    [Column(TypeName = "jsonb")]
    [Required]
    public string Transports { get; set; } = null!;

    public bool UvInitialized { get; set; }

    public bool BackupEligible { get; set; }

    public bool BackupState { get; set; }

    public byte[]? AttestationObject { get; set; }

    public byte[]? AttestationClientDataJson { get; set; }

    [MaxLength(200)]
    public string? Description { get; set; }

    public long CreatedAtUnixTime { get; set; }

    public long UpdatedAtUnixTime { get; set; }

    public static PostgreSqlUserCredentialRecord Create(
        UserCredentialRecord credential,
        Guid id,
        DateTimeOffset createdAt,
        DateTimeOffset updatedAt)
    {
        ArgumentNullException.ThrowIfNull(credential);
        var transportsIntegers = credential.CredentialRecord.Transports.Select(x => (int) x).ToArray();
        var transportsJson = JsonSerializer.Serialize(transportsIntegers);
        var createdAtUnixTime = createdAt.ToUnixTimeSeconds();
        var updatedAtUnixTime = updatedAt.ToUnixTimeSeconds();
        return new()
        {
            Id = id,
            RpId = credential.RpId,
            UserHandle = credential.UserHandle,
            CredentialId = credential.CredentialRecord.Id,
            Type = (int) credential.CredentialRecord.Type,
            Kty = (int) credential.CredentialRecord.PublicKey.Kty,
            Alg = (int) credential.CredentialRecord.PublicKey.Alg,
            Ec2Crv = (int?) credential.CredentialRecord.PublicKey.Ec2?.Crv,
            Ec2X = credential.CredentialRecord.PublicKey.Ec2?.X,
            Ec2Y = credential.CredentialRecord.PublicKey.Ec2?.Y,
            RsaModulusN = credential.CredentialRecord.PublicKey.Rsa?.ModulusN,
            RsaExponentE = credential.CredentialRecord.PublicKey.Rsa?.ExponentE,
            OkpCrv = (int?) credential.CredentialRecord.PublicKey.Okp?.Crv,
            OkpX = credential.CredentialRecord.PublicKey.Okp?.X,
            SignCount = credential.CredentialRecord.SignCount,
            Transports = transportsJson,
            UvInitialized = credential.CredentialRecord.UvInitialized,
            BackupEligible = credential.CredentialRecord.BackupEligible,
            BackupState = credential.CredentialRecord.BackupState,
            AttestationObject = credential.CredentialRecord.AttestationObject,
            AttestationClientDataJson = credential.CredentialRecord.AttestationClientDataJSON,
            Description = credential.Description,
            CreatedAtUnixTime = createdAtUnixTime,
            UpdatedAtUnixTime = updatedAtUnixTime
        };
    }

    public virtual bool TryToUserCredentialRecord([NotNullWhen(true)] out UserCredentialRecord? result)
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

                    ecKey = new(ec2Curve, Ec2X, Ec2Y);
                    break;
                }
            case CoseKeyType.RSA:
                {
                    if (RsaModulusN is null || RsaExponentE is null)
                    {
                        return false;
                    }

                    rsaKey = new(RsaModulusN, RsaExponentE);
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

                    okpKey = new(okpCurve, OkpX);
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
        var transports = Array.Empty<AuthenticatorTransport>();
        if (!string.IsNullOrEmpty(Transports))
        {
            var transportsIntegers = JsonSerializer.Deserialize<int[]>(Transports);
            if (transportsIntegers?.Length > 0)
            {
                var typedTransports = transportsIntegers
                    .Select(x => (AuthenticatorTransport) x)
                    .ToArray();
                foreach (var authenticatorTransport in typedTransports)
                {
                    if (!Enum.IsDefined(authenticatorTransport))
                    {
                        return false;
                    }
                }

                transports = typedTransports;
            }
        }

        if (SignCount is > uint.MaxValue or < uint.MinValue)
        {
            return false;
        }

        var signCount = (uint) SignCount;

        var credentialRecord = new CredentialRecord(
            publicKeyCredentialType,
            CredentialId,
            publicKey,
            signCount,
            transports,
            UvInitialized,
            BackupEligible,
            BackupState,
            AttestationObject,
            AttestationClientDataJson);

        result = new(UserHandle, RpId, Description, credentialRecord);
        return true;
    }
}
