namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation;

/// <summary>
///     <para>10.12.11 TPMU_ATTEST</para>
///     <para>The type-specific attestation information.</para>
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library</a>
///     </para>
///     <para>
///         <a href="https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part2_Structures_pub.pdf">TPM 2.0 Library - Part 2: Structures, Family "2.0", Level 00 Revision 01.59, November 8, 2019</a>
///     </para>
/// </remarks>
public class Attested
{
    // According to the WebAuthn specification, only TPM_ST_ATTEST_CERTIFY is allowed
    // 10.12.11 TPMU_ATTEST
    // Table 131 — Definition of TPMU_ATTEST Union <OUT>
    // | Parameter | Type              | Selector
    // | certify   | TPMS_CERTIFY_INFO | TPM_ST_ATTEST_CERTIFY

    /// <summary>
    ///     Constructs <see cref="Attested" />.
    /// </summary>
    /// <param name="certify">The attested data for TPM2_Certify().</param>
    public Attested(Certify certify)
    {
        Certify = certify;
    }

    /// <summary>
    ///     The attested data for TPM2_Certify().
    /// </summary>
    public Certify Certify { get; }
}
