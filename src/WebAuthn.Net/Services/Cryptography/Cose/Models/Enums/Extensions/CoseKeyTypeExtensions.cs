using System.Collections.Generic;
using System.ComponentModel;

namespace WebAuthn.Net.Services.Cryptography.Cose.Models.Enums.Extensions;

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

    public static IReadOnlySet<CoseAlgorithm> GetSupportedAlgorithms(this CoseKeyType kty)
    {
        return kty switch
        {
            CoseKeyType.EC2 => Ec2,
            CoseKeyType.RSA => Rsa,
            _ => throw new InvalidEnumArgumentException(nameof(kty), (int) kty, typeof(CoseKeyType))
        };
    }
}
