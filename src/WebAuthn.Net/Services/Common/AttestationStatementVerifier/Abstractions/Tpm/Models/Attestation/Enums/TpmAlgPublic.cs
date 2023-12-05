namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation.Enums;

/// <summary>
///     <para>12.2.2 TPMI_ALG_PUBLIC, based on TPM_ALG_ID (UINT16) - TPM_ALG_!ALG.o</para>
///     <para>Type of asymmetric algorithm with a public and private key, used by the TPM module for generating digital signatures in the process of WebAuthn ceremonies.</para>
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library</a>
///     </para>
///     <para>
///         <a href="https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part2_Structures_pub.pdf">TPM 2.0 Library - Part 2: Structures, Family "2.0", Level 00 Revision 01.59, November 8, 2019</a>
///     </para>
/// </remarks>
public enum TpmAlgPublic : ushort
{
    // 12.2.2 TPMI_ALG_PUBLIC
    // Table 192 — Definition of (TPM_ALG_ID) TPMI_ALG_PUBLIC Type
    // | Values         | Comments
    // | TPM_ALG_!ALG.o | All object types
    // | #TPM_RC_TYPE   | response code when a public type is not supported

    /// <summary>
    ///     The RSA algorithm (TPM_ALG_RSA)
    /// </summary>
    /// <remarks>IETF RFC 8017</remarks>
    Rsa = 0x0001,

    /// <summary>
    ///     Prime field ECC (TPM_ALG_ECC)
    /// </summary>
    /// <remarks>ISO/IEC 15946-1</remarks>
    Ecc = 0x0023
}
