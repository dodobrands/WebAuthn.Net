using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace WebAuthn.Net.Storage.MySql.Migrations.Storage.CredentialStorage.Models;

public class MySqlCredentialPublicKeyEc2ParametersRecord : AbstractMySqlPublicKeyRecord
{
    [Column("EcdsaCrv")]
    public int Crv { get; set; }

    [Required]
    [MaxLength(256)]
    [Column("EcdsaX")]
    public byte[] X { get; set; } = null!;

    [Required]
    [MaxLength(256)]
    [Column("EcdsaY")]
    public byte[] Y { get; set; } = null!;
}
