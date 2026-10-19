namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation;

/// <summary>
///     <para>10.11.11 TPMU_ATTEST</para>
///     <para>The type-specific attestation information.</para>
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library</a>
///     </para>
///     <para>
///         <a href="https://cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_2_Structures_Version_185_pub_c0a962a931.pdf">TPM 2.0 Library - Part 2: Structures, Version 185, March 12, 2026</a>
///     </para>
/// </remarks>
public class Attested
{
    // According to the WebAuthn specification, only TPM_ST_ATTEST_CERTIFY is allowed
    // 10.11.11 TPMU_ATTEST
    // Table 153: Definition of TPMU_ATTEST Union
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
