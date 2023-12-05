namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation.Enums;

/// <summary>
///     <para>9.27 TPMI_ALG_HASH, based on TPM_ALG_ID (UINT16) - TPM_ALG_!ALG.H, +TPM_ALG_NULL</para>
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library</a>
///     </para>
///     <para>
///         <a href="https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part2_Structures_pub.pdf">TPM 2.0 Library - Part 2: Structures, Family "2.0", Level 00 Revision 01.59, November 8, 2019</a>
///     </para>
/// </remarks>
public enum TpmAlgIdHash : ushort
{
    // 9.27 TPMI_ALG_HASH
    // A TPMI_ALG_HASH is an interface type of all the hash algorithms implemented on a specific TPM.
    // Table 65 — Definition of (TPM_ALG_ID) TPMI_ALG_HASH Type
    // | Values         | Comments
    // | TPM_ALG_!ALG.H | All hash algorithms defined by the TCG
    // | +TPM_ALG_NULL  |

    /// <summary>
    ///     The SHA1 algorithm (TPM_ALG_SHA1)
    /// </summary>
    /// <remarks>ISO/IEC 10118-3</remarks>
    Sha1 = 0x0004,

    /// <summary>
    ///     The SHA 256 algorithm (TPM_ALG_SHA256)
    /// </summary>
    /// <remarks>ISO/IEC 10118-3</remarks>
    Sha256 = 0x000B,

    /// <summary>
    ///     The SHA 384 algorithm (TPM_ALG_SHA384)
    /// </summary>
    /// <remarks>ISO/IEC 10118-3</remarks>
    Sha384 = 0x000C,

    /// <summary>
    ///     The SHA 512 algorithm (TPM_ALG_SHA512)
    /// </summary>
    /// <remarks>ISO/IEC 10118-3</remarks>
    Sha512 = 0x000D
}
