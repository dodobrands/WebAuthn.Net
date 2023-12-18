using System;
using System.ComponentModel.DataAnnotations;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Text.Json;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums.EC2;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums.OKP;
using WebAuthn.Net.Storage.Credential.Models;

namespace WebAuthn.Net.Storage.SqlServer.Storage.Models;

/// <summary>
///     Microsoft SQL Server-based storage model for storing <see cref="UserCredentialRecord" />.
/// </summary>
public class SqlServerUserCredentialRecord
{
    /// <summary>
    ///     Unique identifier of the record in Microsoft SQL Server.
    /// </summary>
    [Required]
    public Guid Id { get; set; }

    /// <summary>
    ///     The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#rp-id">RP ID</a> to which the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credential-record">credential record</a> is bound.
    /// </summary>
    [Required]
    [MaxLength(256)]
    public string RpId { get; set; } = null!;

    /// <summary>
    ///     Unique user account identifier to which the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credential-record">credential record</a> is bound.
    /// </summary>
    [Required]
    [MaxLength(128)]
    public byte[] UserHandle { get; set; } = null!;

    /// <summary>
    ///     The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credential-id">Credential ID</a> of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential-source">public key credential source</a>.
    /// </summary>
    [Required]
    [MaxLength(1024)]
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
    public long SignCount { get; set; }

    /// <summary>
    ///     The value returned from <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorattestationresponse-gettransports">getTransports()</a> when the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential-source">public key credential source</a> was <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#registration">registered</a>.
    /// </summary>
    /// <remarks>
    ///     <para>
    ///         Modifying or removing <a href="https://infra.spec.whatwg.org/#list-item">items</a> from the value returned from <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorattestationresponse-gettransports">getTransports()</a> could negatively impact
    ///         user experience, or even prevent use of the corresponding credential.
    ///     </para>
    ///     <para>For storage in Microsoft SQL Server, the values are transformed into json ('nvarchar(max)' data type).</para>
    /// </remarks>
    [Required]
    public string Transports { get; set; } = null!;

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
    ///     Credential record update date in unixtime seconds format.
    /// </summary>
    public long UpdatedAtUnixTime { get; set; }

    /// <summary>
    ///     Creates <see cref="SqlServerUserCredentialRecord" />.
    /// </summary>
    /// <param name="credential">Credential record bound to a user account.</param>
    /// <param name="id">Unique identifier of the record in Microsoft SQL Server.</param>
    /// <param name="createdAt">Creation date of the credential record.</param>
    /// <param name="updatedAt">Credential record update date.</param>
    /// <returns>An instance of <see cref="SqlServerUserCredentialRecord" />.</returns>
    public static SqlServerUserCredentialRecord Create(
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

    /// <summary>
    ///     If possible - converts the current record into a <see cref="UserCredentialRecord" />.
    /// </summary>
    /// <param name="result">Output parameter. Contains an instance of <see cref="UserCredentialRecord" /> if the method returns <see langword="true" />, otherwise - <see langword="null" />.</param>
    /// <returns><see langword="true" /> if the conversion is successful, otherwise - <see langword="false" />.</returns>
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
