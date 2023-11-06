using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace WebAuthn.Net.Storage.MySql.Migrations.Storage.CredentialStorage.Models;

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
}
