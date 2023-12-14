using System.Collections.Generic;
using System.ComponentModel;

namespace WebAuthn.Net.Services.Serialization.Cose.Models.Enums.Extensions;

/// <summary>
///     Extension methods for <see cref="CoseKeyType" />.
/// </summary>
public static class CoseKeyTypeExtensions
{
    private static readonly IReadOnlySet<CoseAlgorithm> Ec2 = new HashSet<CoseAlgorithm>
    {
        CoseAlgorithm.ES512,
        CoseAlgorithm.ES384,
        CoseAlgorithm.ES256
    };

    private static readonly IReadOnlySet<CoseAlgorithm> Rsa = new HashSet<CoseAlgorithm>
    {
        CoseAlgorithm.RS1,
        CoseAlgorithm.RS512,
        CoseAlgorithm.RS384,
        CoseAlgorithm.RS256,
        CoseAlgorithm.PS512,
        CoseAlgorithm.PS384,
        CoseAlgorithm.PS256
    };

    private static readonly IReadOnlySet<CoseAlgorithm> Okp = new HashSet<CoseAlgorithm>
    {
        CoseAlgorithm.EdDSA
    };

    /// <summary>
    ///     Returns a set of supported algorithms for the given COSE key type.
    /// </summary>
    /// <param name="kty">COSE Key type</param>
    /// <returns>A set of supported algorithms for the given COSE key type.</returns>
    /// <exception cref="InvalidEnumArgumentException"><paramref name="kty" /> contains a value that is not defined in <see cref="CoseKeyType" /></exception>
    public static IReadOnlySet<CoseAlgorithm> GetSupportedAlgorithms(this CoseKeyType kty)
    {
        return kty switch
        {
            CoseKeyType.EC2 => Ec2,
            CoseKeyType.RSA => Rsa,
            CoseKeyType.OKP => Okp,
            _ => throw new InvalidEnumArgumentException(nameof(kty), (int) kty, typeof(CoseKeyType))
        };
    }
}
