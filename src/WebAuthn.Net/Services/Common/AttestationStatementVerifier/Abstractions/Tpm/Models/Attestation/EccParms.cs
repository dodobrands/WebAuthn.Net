using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation.Abstractions;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation.Enums;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation;

/// <summary>
///     <para>12.2.3.5 TPMS_ECC_PARMS (Table 229)</para>
///     <para>This structure contains the parameters for prime modulus ECC.</para>
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library</a>
///     </para>
///     <para>
///         <a href="https://cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_2_Structures_Version_185_pub_c0a962a931.pdf">TPM 2.0 Library - Part 2: Structures, Version 185, March 12, 2026</a>
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
