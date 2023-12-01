using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation.Abstractions;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation.Enums;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation;

/// <summary>
///     12.2.3.6 TPMS_ECC_PARMS
/// </summary>
public class EccParms : AbstractPublicParms
{
    public EccParms(TpmiEccCurve curveId)
    {
        CurveId = curveId;
    }

    public TpmiEccCurve CurveId { get; }
}
