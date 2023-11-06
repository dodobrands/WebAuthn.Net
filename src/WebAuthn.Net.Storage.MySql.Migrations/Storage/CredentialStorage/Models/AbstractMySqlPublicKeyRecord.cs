using System.ComponentModel.DataAnnotations;

namespace WebAuthn.Net.Storage.MySql.Migrations.Storage.CredentialStorage.Models;

public abstract class AbstractMySqlPublicKeyRecord
{
    [Required]
    [MaxLength(16)]
    [Key]
    public byte[] UserCredentialRecordId { get; set; } = null!;

    public MySqlUserCredentialRecord UserCredentialRecord { get; set; } = null!;

    public int Kty { get; set; }

    public int Alg { get; set; }
}
