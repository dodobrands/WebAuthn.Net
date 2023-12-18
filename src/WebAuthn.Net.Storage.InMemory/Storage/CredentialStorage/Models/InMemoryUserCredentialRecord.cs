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

/// <summary>
///     In-memory model for storing <see cref="UserCredentialRecord" />.
/// </summary>
public class InMemoryUserCredentialRecord
{
    /// <summary>
    ///     The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#rp-id">RP ID</a> to which the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credential-record">credential record</a> is bound.
    /// </summary>
    public string RpId { get; set; } = null!;

    /// <summary>
    ///     Unique user account identifier to which the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credential-record">credential record</a> is bound.
    /// </summary>
    public byte[] UserHandle { get; set; } = null!;

    /// <summary>
    ///     The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credential-id">Credential ID</a> of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential-source">public key credential source</a>.
    /// </summary>
    public byte[] CredentialId { get; set; } = null!;

    /// <summary>
    ///     The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential-source-type">type</a> of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential-source">public key credential source</a>.
    /// </summary>
    public int Type { get; set; }

    /// <summary>
    ///     The key type defined by the "kty" member of a COSE_Key object.
    /// </summary>
    public int Kty { get; set; }

    /// <summary>
    ///     The identifier of the cryptographic algorithm of this public key.
    /// </summary>
    public int Alg { get; set; }

    /// <summary>
    ///     COSE elliptic curve for a public key in EC2 format.
    /// </summary>
    public int? Ec2Crv { get; set; }

    /// <summary>
    ///     X coordinate (for a key in EC2 format).
    /// </summary>
    [MaxLength(256)]
    public byte[]? Ec2X { get; set; }

    /// <summary>
    ///     Y coordinate (for a key in EC2 format).
    /// </summary>
    [MaxLength(256)]
    public byte[]? Ec2Y { get; set; }

    /// <summary>
    ///     RSA modulus N.
    /// </summary>
    [MaxLength(8192 / 8)]
    public byte[]? RsaModulusN { get; set; }

    // NIST SP 800-56B Rev. 2
    // https://doi.org/10.6028/NIST.SP.800-56Br2
    // 6.2 Criteria for RSA Key Pairs for Key Establishment
    // 6.2.1 Definition of a Key Pair
    // The public exponent e shall be an odd integer that is selected prior to the generation of p and q such that:
    // 65,537 ≤ e < 2^256
    /// <summary>
    ///     RSA exponent E.
    /// </summary>
    [MaxLength(256 / 8)]
    public byte[]? RsaExponentE { get; set; }

    /// <summary>
    ///     COSE elliptic curve for a public key in OKP format.
    /// </summary>
    public int? OkpCrv { get; set; }

    /// <summary>
    ///     Public Key (for a key in OKP format).
    /// </summary>
    [MaxLength(32)]
    public byte[]? OkpX { get; set; }

    /// <summary>
    ///     The latest value of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-signcount">signature counter</a> in the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator-data">authenticator data</a> from any
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#ceremony">ceremony</a> using the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential-source">public key credential source</a>.
    /// </summary>
    public uint SignCount { get; set; }

    /// <summary>
    ///     The value returned from <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorattestationresponse-gettransports">getTransports()</a> when the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential-source">public key credential source</a> was <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#registration">registered</a>.
    /// </summary>
    /// <remarks>
    ///     Modifying or removing <a href="https://infra.spec.whatwg.org/#list-item">items</a> from the value returned from <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorattestationresponse-gettransports">getTransports()</a> could negatively impact user
    ///     experience, or even prevent use of the corresponding credential.
    /// </remarks>
    public int[] Transports { get; set; } = null!;

    /// <summary>
    ///     A Boolean value indicating whether any <a href="https://w3c.github.io/webappsec-credential-management/#concept-credential">credential</a> from this <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential-source">public key credential source</a> has
    ///     had the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-flags-uv">UV</a> <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-flags">flag</a> set.
    /// </summary>
    public bool UvInitialized { get; set; }

    /// <summary>
    ///     The value of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-flags-be">BE</a> <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-flags">flag</a> when the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential-source">public key credential source</a> was created.
    /// </summary>
    public bool BackupEligible { get; set; }

    /// <summary>
    ///     The latest value of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-flags-bs">BS</a> <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-flags">flag</a> in the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator-data">authenticator data</a> from any <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#ceremony">ceremony</a> using the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential-source">public key credential source</a>.
    /// </summary>
    public bool BackupState { get; set; }

    /// <summary>
    ///     OPTIONAL. The value of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorattestationresponse-attestationobject">attestationObject</a> attribute when the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential-source">public key credential</a> source was <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#registration">registered</a>. Storing this enables the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> to reference the credential's <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-statement">attestation statement</a> at a later time.
    /// </summary>
    public byte[]? AttestationObject { get; set; }

    /// <summary>
    ///     OPTIONAL. The value of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorresponse-clientdatajson">clientDataJSON</a> attribute when the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential-source">public key credential source</a> was <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#registration">registered</a>. Storing this in combination with the above
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#abstract-opdef-credential-record-attestationobject">attestationObject</a> <a href="https://infra.spec.whatwg.org/#struct-item">item</a> enables the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> to re-verify the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-signature">attestation signature</a> at a later time.
    /// </summary>
    public byte[]? AttestationClientDataJson { get; set; }

    /// <summary>
    ///     Description of the credential.
    /// </summary>
    [MaxLength(200)]
    public string? Description { get; set; }

    /// <summary>
    ///     Creation date of the credential record in unixtime seconds format.
    /// </summary>
    public long CreatedAtUnixTime { get; set; }

    /// <summary>
    ///     Update date of the credential record in unixtime seconds format.
    /// </summary>
    public long UpdatedAtUnixTime { get; set; }

    /// <summary>
    ///     Creates <see cref="InMemoryUserCredentialRecord" />.
    /// </summary>
    /// <param name="record">Credential record bound to a user account.</param>
    /// <param name="createdAt">The date when the record was created.</param>
    /// <param name="updatedAt">The date when the record was updated.</param>
    /// <returns>An instance of <see cref="InMemoryUserCredentialRecord" /></returns>
    public static InMemoryUserCredentialRecord Create(UserCredentialRecord record, DateTimeOffset createdAt, DateTimeOffset updatedAt)
    {
        ArgumentNullException.ThrowIfNull(record);
        var result = new InMemoryUserCredentialRecord
        {
            RpId = record.RpId,
            UserHandle = CopyArray(record.UserHandle),
            CredentialId = CopyArray(record.CredentialRecord.Id),
            Type = (int) record.CredentialRecord.Type,
            Kty = (int) record.CredentialRecord.PublicKey.Kty,
            Alg = (int) record.CredentialRecord.PublicKey.Alg,
            Ec2Crv = (int?) record.CredentialRecord.PublicKey.Ec2?.Crv,
            Ec2X = record.CredentialRecord.PublicKey.Ec2?.X,
            Ec2Y = record.CredentialRecord.PublicKey.Ec2?.Y,
            RsaModulusN = record.CredentialRecord.PublicKey.Rsa?.ModulusN,
            RsaExponentE = record.CredentialRecord.PublicKey.Rsa?.ExponentE,
            OkpCrv = (int?) record.CredentialRecord.PublicKey.Okp?.Crv,
            OkpX = record.CredentialRecord.PublicKey.Okp?.X,
            SignCount = record.CredentialRecord.SignCount,
            Transports = record.CredentialRecord.Transports.Select(x => (int) x).ToArray(),
            UvInitialized = record.CredentialRecord.UvInitialized,
            BackupEligible = record.CredentialRecord.BackupEligible,
            BackupState = record.CredentialRecord.BackupState,
            AttestationObject = CopyArray(record.CredentialRecord.AttestationObject),
            AttestationClientDataJson = CopyArray(record.CredentialRecord.AttestationClientDataJSON),
            Description = record.Description,
            CreatedAtUnixTime = createdAt.ToUnixTimeSeconds(),
            UpdatedAtUnixTime = updatedAt.ToUnixTimeSeconds()
        };
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

    /// <summary>
    ///     If possible - converts the current record into a <see cref="PublicKeyCredentialDescriptor" />.
    /// </summary>
    /// <param name="result">Output parameter. Contains an instance of <see cref="PublicKeyCredentialDescriptor" /> if the method returns <see langword="true" />, otherwise - <see langword="null" />.</param>
    /// <returns><see langword="true" /> if the conversion is successful, otherwise - <see langword="false" />.</returns>
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

    /// <summary>
    ///     If possible - converts the current record into a <see cref="UserCredentialRecord" />.
    /// </summary>
    /// <param name="result">Output parameter. Contains an instance of <see cref="UserCredentialRecord" /> if the method returns <see langword="true" />, otherwise - <see langword="null" />.</param>
    /// <returns><see langword="true" /> if the conversion is successful, otherwise - <see langword="false" />.</returns>
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

        result = new(UserHandle, RpId, Description, credentialRecord);
        return true;
    }
}
