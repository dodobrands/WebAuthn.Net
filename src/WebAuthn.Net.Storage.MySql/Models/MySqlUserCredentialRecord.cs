using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Enums;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Enums.EC2;
using WebAuthn.Net.Storage.Credential.Models;

namespace WebAuthn.Net.Storage.MySql.Models;

public class MySqlUserCredentialRecord
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

    [Column(TypeName = "json")]
    public int[] Transports { get; set; } = null!;

    public bool UvInitialized { get; set; }

    public bool BackupEligible { get; set; }

    public bool BackupState { get; set; }

    public byte[]? AttestationObject { get; set; }

    public byte[]? AttestationClientDataJson { get; set; }

    public long CreatedAtUnixTime { get; set; }

    public UserCredentialRecord? MapToRecord()
    {

        if (!Enum.TryParse<PublicKeyCredentialType>($"{Type}", out var publicKeyCredentialType))
        {
            return null;
        }

        if (!Enum.TryParse<CoseKeyType>($"{Kty}", out var coseKeyType))
        {
        }

        if (!Enum.TryParse<CoseAlgorithm>($"{Alg}", out var coseAlgorithm))
        {
            return null;
        }

        CredentialPublicKeyRsaParametersRecord? rsaKey = null;
        CredentialPublicKeyEc2ParametersRecord? ecKey = null;
        if (coseKeyType is CoseKeyType.RSA)
        {
            rsaKey = new (RsaModulusN!, RsaExponentE!);
        }

        if (coseKeyType is CoseKeyType.EC2)
        {
            if (Enum.TryParse<CoseEllipticCurve>($"{EcdsaCrv}", out var ecdsaCurve))
            {
                ecKey = new(ecdsaCurve, EcdsaX!, EcdsaY!);
            }
        }

        var publicKey = new CredentialPublicKeyRecord(
            coseKeyType,
            coseAlgorithm,
            rsaKey,
            ecKey
        );

        var authenticatorTransports = Transports
            .Select(x => (AuthenticatorTransport) x)
            .ToArray();

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

        return new (UserHandle, RpId, credentialRecord);
    }
}
