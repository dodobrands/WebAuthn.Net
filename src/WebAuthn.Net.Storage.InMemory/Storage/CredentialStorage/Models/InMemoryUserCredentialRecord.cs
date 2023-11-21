using System;
using System.ComponentModel.DataAnnotations;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using WebAuthn.Net.Models.Protocol;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums.EC2;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums.OKP;
using WebAuthn.Net.Storage.Credential.Models;

namespace WebAuthn.Net.Storage.InMemory.Storage.CredentialStorage.Models;

public class InMemoryUserCredentialRecord
{
    public InMemoryUserCredentialRecord(UserCredentialRecord record, DateTimeOffset createdAt)
    {
        ArgumentNullException.ThrowIfNull(record);
        RpId = record.RpId;
        UserHandle = CopyArray(record.UserHandle);
        CredentialId = CopyArray(record.CredentialRecord.Id);
        Type = (int) record.CredentialRecord.Type;
        Kty = (int) record.CredentialRecord.PublicKey.Kty;
        Alg = (int) record.CredentialRecord.PublicKey.Alg;
        Ec2Crv = (int?) record.CredentialRecord.PublicKey.Ec2?.Crv;
        Ec2X = record.CredentialRecord.PublicKey.Ec2?.X;
        Ec2Y = record.CredentialRecord.PublicKey.Ec2?.Y;
        RsaModulusN = record.CredentialRecord.PublicKey.Rsa?.ModulusN;
        RsaExponentE = record.CredentialRecord.PublicKey.Rsa?.ExponentE;
        OkpCrv = (int?) record.CredentialRecord.PublicKey.Okp?.Crv;
        OkpX = record.CredentialRecord.PublicKey.Okp?.X;
        SignCount = record.CredentialRecord.SignCount;
        Transports = record.CredentialRecord.Transports.Select(x => (int) x).ToArray();
        UvInitialized = record.CredentialRecord.UvInitialized;
        BackupEligible = record.CredentialRecord.BackupEligible;
        BackupState = record.CredentialRecord.BackupState;
        AttestationObject = CopyArray(record.CredentialRecord.AttestationObject);
        AttestationClientDataJson = CopyArray(record.CredentialRecord.AttestationClientDataJSON);
        CreatedAtUnixTime = createdAt.ToUnixTimeSeconds();
    }

    public string RpId { get; }

    public byte[] UserHandle { get; }

    public byte[] CredentialId { get; }

    public int Type { get; }

    public int Kty { get; }

    public int Alg { get; }

    public int? Ec2Crv { get; }

    [MaxLength(256)]
    public byte[]? Ec2X { get; }

    [MaxLength(256)]
    public byte[]? Ec2Y { get; }

    [MaxLength(8192 / 8)]
    public byte[]? RsaModulusN { get; }

    // NIST SP 800-56B Rev. 2
    // https://doi.org/10.6028/NIST.SP.800-56Br2
    // 6.2 Criteria for RSA Key Pairs for Key Establishment
    // 6.2.1 Definition of a Key Pair
    // The public exponent e shall be an odd integer that is selected prior to the generation of p and q such that:
    // 65,537 ≤ e < 2^256
    [MaxLength(256 / 8)]
    public byte[]? RsaExponentE { get; }

    public int? OkpCrv { get; }

    [MaxLength(32)]
    public byte[]? OkpX { get; }

    public uint SignCount { get; }

    public int[] Transports { get; }

    public bool UvInitialized { get; }

    public bool BackupEligible { get; }

    public bool BackupState { get; }

    public byte[]? AttestationObject { get; }

    public byte[]? AttestationClientDataJson { get; }

    public long CreatedAtUnixTime { get; }

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

    public virtual bool TryMapToDescriptor([NotNullWhen(true)] out PublicKeyCredentialDescriptor? result)
    {
        result = null;
        var publicKeyCredentialType = (PublicKeyCredentialType) Type;
        if (!Enum.IsDefined(publicKeyCredentialType))
        {
            return false;
        }

        var credentialId = CopyArray(CredentialId);
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


    public virtual bool TryMapToUserCredentialRecord([NotNullWhen(true)] out UserCredentialRecord? result)
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
            CredentialId,
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
