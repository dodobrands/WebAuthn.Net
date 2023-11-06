using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace WebAuthn.Net.Storage.MySql.Migrations.Storage.CredentialStorage.Models;

public class MySqlCredentialPublicKeyRsaParametersRecord : AbstractMySqlPublicKeyRecord
{
    [Required]
    [MaxLength(8192 / 8)]
    [Column("RsaModulusN")]
    public byte[] ModulusN { get; set; } = null!;

    // NIST SP 800-56B Rev. 2
    // https://doi.org/10.6028/NIST.SP.800-56Br2
    // 6.2 Criteria for RSA Key Pairs for Key Establishment
    // 6.2.1 Definition of a Key Pair
    // The public exponent e shall be an odd integer that is selected prior to the generation of p and q such that:
    // 65,537 ≤ e < 2^256
    [Required]
    [MaxLength(256 / 8)]
    [Column("RsaExponentE")]
    public byte[] ExponentE { get; set; } = null!;
}
