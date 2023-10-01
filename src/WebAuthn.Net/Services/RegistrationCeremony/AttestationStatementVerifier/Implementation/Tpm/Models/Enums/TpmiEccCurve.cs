namespace WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Implementation.Tpm.Models.Enums;

/// <summary>
///     TPMI_ECC_CURVE, based on TPM_ECC_CURVE (UINT16).
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library</a>
///     </para>
///     <para>
///         <a href="https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part2_Structures_pub.pdf">TPM 2.0 Library - Part 2: Structures, Family "2.0", Level 00 Revision 01.59, November 8, 2019</a>
///     </para>
///     <para>11.2.5.5 TPMI_ECC_CURVE</para>
/// </remarks>
public enum TpmiEccCurve : ushort
{
    /// <summary>
    ///     TPM_ECC_NIST_P256
    /// </summary>
    TpmEccNistP256 = 0x0003,

    /// <summary>
    ///     TPM_ECC_NIST_P384
    /// </summary>
    TpmEccNistP384 = 0x0004,

    /// <summary>
    ///     TPM_ECC_NIST_P521
    /// </summary>
    TpmEccNistP521 = 0x0005
}
