using System.Diagnostics.CodeAnalysis;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation.Enums;

/// <summary>
///     <para>9.36 TPMI_ALG_KDF, based on TPM_ALG_ID (UINT16) - TPM_ALG_MGF1, TPM_ALG_KDF2, TPM_ALG_KDF1_SP800_56A, TPM_ALG_KDF1_SP800_108, TPM_ALG_HKDF, +TPM_ALG_NULL</para>
///     <para>
///         The members are the wire-format vocabulary of TPMI_ALG_KDF (Table 82).
///         For the kdf field of TPMS_ECC_PARMS the decoder accepts only <see cref="TpmAlgNull" />: Part 2 Table 229 allows a non-NULL kdf only for an unrestricted decryption TPM_ALG_ECDH key ("Shall be NULL in all other cases (TPM_RC_KDF)"),
///         and such a key can never be a WebAuthn credential key; the reference implementation (SchemeChecks) requires TPM_ALG_NULL unconditionally.
///     </para>
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library</a>
///     </para>
///     <para>
///         <a href="https://cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_2_Structures_Version_185_pub_c0a962a931.pdf">TPM 2.0 Library - Part 2: Structures, Version 185, March 12, 2026</a>
///     </para>
/// </remarks>
public enum TpmiAlgKdf : ushort
{
    // 9.36 TPMI_ALG_KDF
    // TPMI_ALG_KDF is an interface type of all the key and mask derivation functions implemented on a specific TPM.
    // Table 82 — Definition of (TPM_ALG_ID) TPMI_ALG_KDF Type
    // | Values                 | Comments
    // | TPM_ALG_MGF1           |
    // | TPM_ALG_KDF2           |
    // | TPM_ALG_KDF1_SP800_56A |
    // | TPM_ALG_KDF1_SP800_108 |
    // | TPM_ALG_HKDF           |
    // | +TPM_ALG_NULL          |
    // | #TPM_RC_KDF            |

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
    /// HMAC-based Extract-and-Expand Key Derivation Function
    /// </summary>
    /// <remarks>
    /// <para>TPM_ALG_HKDF</para>
    /// <para>IETF RFC 5869</para>
    /// <para>Added to TPMI_ALG_KDF in version 185 (Table 82); not present in the V184 reference implementation.</para>
    /// </remarks>
    TpmAlgHkdf = 0x001F,

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
