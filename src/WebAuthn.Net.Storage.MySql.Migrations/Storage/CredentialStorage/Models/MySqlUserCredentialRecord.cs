using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Diagnostics.CodeAnalysis;

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
    public AbstractMySqlPublicKeyRecord PublicKey { get; set; } = null!;
    public uint SignCount { get; set; }

    [Column(TypeName = "json")]
    public int[] Transports { get; set; } = null!;

    public bool UvInitialized { get; set; }
    public bool BackupEligible { get; set; }
    public bool BackupState { get; set; }
    public byte[]? AttestationObject { get; set; }

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    public byte[]? AttestationClientDataJSON { get; set; }
}
