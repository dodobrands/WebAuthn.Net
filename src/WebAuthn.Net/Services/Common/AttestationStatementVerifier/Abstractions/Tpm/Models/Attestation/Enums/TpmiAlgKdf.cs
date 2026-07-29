using System.Diagnostics.CodeAnalysis;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation.Enums;

/// <summary>
///     <para>9.32 TPMI_ALG_KDF (Key and Mask Generation Functions), based on TPM_ALG_ID (UINT16) - TPM_ALG_!ALG.HM, +TPM_ALG_NULL</para>
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library</a>
///     </para>
///     <para>
///         <a href="https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part2_Structures_pub.pdf">TPM 2.0 Library - Part 2: Structures, Family "2.0", Level 00 Revision 01.59, November 8, 2019</a>
///     </para>
/// </remarks>
public enum TpmiAlgKdf : ushort
{
    /// <summary>
    ///     Null algorithm
    /// </summary>
    /// <remarks>
    /// <para>TPM_ALG_NULL</para>
    /// <para>TCG TPM 2.0 library specification</para>
    /// </remarks>
    TpmAlgNull = 0x0010,

    /// <summary>
    /// Hash-based mask-generation function
    /// </summary>
    /// <remarks>
    /// <para>TPM_ALG_MGF1</para>
    /// <para>IEEE Std 1363-2000</para>
    /// <para>IEEE Std 1363a-2004</para>
    /// </remarks>
    TpmAlgMgf1 = 0x0007,

    /// <summary>
    /// Concatenation key derivation function (approved alternative 1) clause 5.8.1
    /// </summary>
    /// <remarks>
    /// <para>TPM_ALG_KDF1_SP800_56A</para>
    /// <para>NIST SP800-56A</para>
    /// </remarks>
    [SuppressMessage("ReSharper", "InconsistentNaming")]
    TpmAlgKdf1Sp800_56a = 0x0020,

    /// <summary>
    /// Key derivation function KDF2 clause 13.2
    /// </summary>
    /// <remarks>
    /// <para>TPM_ALG_KDF2</para>
    /// <para>IEEE Std 1363a-2004</para>
    /// </remarks>
    TpmAlgKdf2 = 0x0021,

    /// <summary>
    /// A key derivation method clause 5.1 KDF in Counter Mode
    /// </summary>
    /// <remarks>
    /// <para>TPM_ALG_KDF1_SP800_108</para>
    /// <para>NIST SP800-108</para>
    /// </remarks>
    [SuppressMessage("ReSharper", "InconsistentNaming")]
    TpmAlgKdf1Sp800_108 = 0x0022
}
