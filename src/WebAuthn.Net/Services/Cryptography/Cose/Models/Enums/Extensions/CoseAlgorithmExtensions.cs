using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Enums.EC2;

namespace WebAuthn.Net.Services.Cryptography.Cose.Models.Enums.Extensions;

/// <summary>
///     Extension methods for <see cref="CoseAlgorithm" />.
/// </summary>
public static class CoseAlgorithmIdentifierExtensions
{
    private static readonly IReadOnlySet<CoseEllipticCurve> Es512 = new HashSet<CoseEllipticCurve>
    {
        CoseEllipticCurve.P521
    };

    private static readonly IReadOnlySet<CoseEllipticCurve> Es384 = new HashSet<CoseEllipticCurve>
    {
        CoseEllipticCurve.P384
    };

    private static readonly IReadOnlySet<CoseEllipticCurve> Es256 = new HashSet<CoseEllipticCurve>
    {
        CoseEllipticCurve.P256
    };

    public static bool TryGetSupportedEllipticCurves(
        this CoseAlgorithm coseAlgorithm,
        [NotNullWhen(true)] out IReadOnlySet<CoseEllipticCurve>? ellipticCurves)
    {
        switch (coseAlgorithm)
        {
            case CoseAlgorithm.RS1:
            case CoseAlgorithm.RS512:
            case CoseAlgorithm.RS384:
            case CoseAlgorithm.RS256:
            case CoseAlgorithm.PS512:
            case CoseAlgorithm.PS384:
            case CoseAlgorithm.PS256:
                {
                    ellipticCurves = null;
                    return false;
                }
            case CoseAlgorithm.ES512:
                {
                    ellipticCurves = Es512;
                    return true;
                }
            case CoseAlgorithm.ES384:
                {
                    ellipticCurves = Es384;
                    return true;
                }
            case CoseAlgorithm.ES256:
                {
                    ellipticCurves = Es256;
                    return true;
                }
            default:
                throw new InvalidEnumArgumentException(nameof(coseAlgorithm), (int) coseAlgorithm, typeof(CoseAlgorithm));
        }
    }
}
