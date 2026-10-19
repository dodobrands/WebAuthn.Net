namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation.Abstractions;

/// <summary>
///     <para>Base type for the type-specific parameters of TPMU_PUBLIC_PARMS (12.2.3.9, Table 233): rsaDetail (TPMS_RSA_PARMS, 12.2.3.4) or eccDetail (TPMS_ECC_PARMS, 12.2.3.5).</para>
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library</a>
///     </para>
///     <para>
///         <a href="https://cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_2_Structures_Version_185_pub_c0a962a931.pdf">TPM 2.0 Library - Part 2: Structures, Version 185, March 12, 2026</a>
///     </para>
/// </remarks>
public abstract class AbstractPublicParms
{
}
