using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation.Abstractions;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation.Enums;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation;

/// <summary>
///     <para>12.2.3.6 TPMS_ECC_PARMS</para>
///     <para>This structure contains the parameters for prime modulus ECC.</para>
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library</a>
///     </para>
///     <para>
///         <a href="https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part2_Structures_pub.pdf">TPM 2.0 Library - Part 2: Structures, Family "2.0", Level 00 Revision 01.59, November 8, 2019</a>
///     </para>
/// </remarks>
public class EccParms : AbstractPublicParms
{
    /// <summary>
    ///     Constructs <see cref="EccParms" />.
    /// </summary>
    /// <param name="curveId">ECC curve ID.</param>
    public EccParms(TpmiEccCurve curveId)
    {
        CurveId = curveId;
    }

    /// <summary>
    ///     ECC curve ID.
    /// </summary>
    public TpmiEccCurve CurveId { get; }
}
