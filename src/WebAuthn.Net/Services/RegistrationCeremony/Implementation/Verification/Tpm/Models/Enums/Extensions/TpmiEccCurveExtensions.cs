using System.Diagnostics.CodeAnalysis;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Enums.EC2;

namespace WebAuthn.Net.Services.RegistrationCeremony.Implementation.Verification.Tpm.Models.Enums.Extensions;

public static class TpmiEccCurveExtensions
{
    public static bool TryToCoseEllipticCurve(this TpmiEccCurve tpmiEccCurve, [NotNullWhen(true)] out CoseEllipticCurve? crv)
    {
        switch (tpmiEccCurve)
        {
            case TpmiEccCurve.TpmEccNistP256:
                {
                    crv = CoseEllipticCurve.P256;
                    return true;
                }
            case TpmiEccCurve.TpmEccNistP384:
                {
                    crv = CoseEllipticCurve.P384;
                    return true;
                }
            case TpmiEccCurve.TpmEccNistP521:
                {
                    crv = CoseEllipticCurve.P521;
                    return true;
                }
            default:
                {
                    crv = null;
                    return false;
                }
        }
    }
}
