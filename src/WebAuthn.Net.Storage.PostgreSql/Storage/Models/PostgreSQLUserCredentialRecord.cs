using System;
using System.ComponentModel.DataAnnotations;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Enums;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Enums.EC2;
using WebAuthn.Net.Storage.Credential.Models;

namespace WebAuthn.Net.Storage.PostgreSql.Storage.Models;

public class PostgreSqlUserCredentialRecord
{
    [Required]
    [MaxLength(16)]
    public byte[] Id { get; set; } = null!;

    [Required]
    [MaxLength(300)]
    public string RpId { get; set; } = null!;

    [Required]
    [MaxLength(300)]
    public byte[] UserHandle { get; set; } = null!;

    [Required]
    [MaxLength(1024)]
    public byte[] CredentialId { get; set; } = null!;

    public int Type { get; set; }

    public int Kty { get; set; }

    public int Alg { get; set; }

    public int? EcdsaCrv { get; set; }

    [MaxLength(256)]
    public byte[]? EcdsaX { get; set; }

    [MaxLength(256)]
    public byte[]? EcdsaY { get; set; }

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

    public uint SignCount { get; set; }

    public int[] Transports { get; set; } = null!;

    public bool UvInitialized { get; set; }

    public bool BackupEligible { get; set; }

    public bool BackupState { get; set; }

    public byte[]? AttestationObject { get; set; }

    public byte[]? AttestationClientDataJson { get; set; }

    public long CreatedAtUnixTime { get; set; }

    public bool TryMapToResult([NotNullWhen(true)] out UserCredentialRecord? result)
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

        switch (coseKeyType)
        {
            case CoseKeyType.EC2:
                {
                    if (!EcdsaCrv.HasValue)
                    {
                        return false;
                    }

                    var ecdsaCurve = (CoseEllipticCurve) EcdsaCrv.Value;
                    if (!Enum.IsDefined(ecdsaCurve) || EcdsaX is null || EcdsaY is null)
                    {
                        return false;
                    }

                    ecKey = new(ecdsaCurve, EcdsaX, EcdsaY);
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
            default:
                return false;
        }

        var publicKey = new CredentialPublicKeyRecord(
            coseKeyType,
            coseAlgorithm,
            rsaKey,
            ecKey);

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

        var credentialRecord = new CredentialRecord(
            publicKeyCredentialType,
            Id,
            publicKey,
            SignCount,
            authenticatorTransports,
            UvInitialized,
            BackupEligible,
            BackupState,
            AttestationObject,
            AttestationClientDataJson
        );

        result = new(UserHandle, RpId, credentialRecord);
        return true;
    }
}
