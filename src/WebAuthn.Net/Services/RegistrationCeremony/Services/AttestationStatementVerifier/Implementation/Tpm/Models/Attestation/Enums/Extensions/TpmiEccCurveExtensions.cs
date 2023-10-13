using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Implementation.Tpm.Models.Attestation.Enums.Extensions;

public static class TpmiEccCurveExtensions
{
    public static bool TryToEcCurve(this TpmiEccCurve tpmiEccCurve, [NotNullWhen(true)] out ECCurve? crv)
    {
        switch (tpmiEccCurve)
        {
            case TpmiEccCurve.TpmEccNistP256:
                {
                    crv = ECCurve.NamedCurves.nistP256;
                    return true;
                }
            case TpmiEccCurve.TpmEccNistP384:
                {
                    crv = ECCurve.NamedCurves.nistP384;
                    return true;
                }
            case TpmiEccCurve.TpmEccNistP521:
                {
                    crv = ECCurve.NamedCurves.nistP521;
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
