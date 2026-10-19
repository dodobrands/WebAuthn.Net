namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation.Enums;

/// <summary>
///     <para>9.34 TPMI_ALG_SYM_OBJECT, based on TPM_ALG_ID (UINT16) - TPM_ALG_TDES, TPM_ALG_AES, TPM_ALG_SM4, TPM_ALG_CAMELLIA, +TPM_ALG_NULL</para>
///     <para>
///         Only <see cref="TpmAlgNull" /> is a member on purpose. The symmetric field of TPMS_RSA_PARMS / TPMS_ECC_PARMS may be a block cipher only for a restricted decryption key (a Storage Key),
///         which can never be a WebAuthn credential key; for every other asymmetric key it "shall be set to TPM_ALG_NULL" (Tables 228 and 229; reference SchemeChecks returns TPM_RC_SYMMETRIC otherwise).
///         The other values of Table 80 are listed below for documentation only.
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
public enum TpmiAlgSymObject : ushort
{
    // 9.34 TPMI_ALG_SYM_OBJECT
    // TPMI_ALG_SYM_OBJECT is an interface type of all the TCG-defined symmetric algorithms that may be used as companion symmetric encryption algorithm for an asymmetric object.
    // All algorithms in this list shall be block ciphers usable in Cipher Feedback (CFB).
    // Note: TPM_ALG_XOR is not allowed in this list.
    // Table 80 — Definition of (TPM_ALG_ID) TPMI_ALG_SYM_OBJECT Type
    // | Values           | Comments
    // | TPM_ALG_TDES     | Deprecated: TDES is deprecated. See Part 0.
    // | TPM_ALG_AES      |
    // | TPM_ALG_SM4      |
    // | TPM_ALG_CAMELLIA |
    // | +TPM_ALG_NULL    | required
    // | #TPM_RC_SYMMETRIC|
    // Values (6.3 TPM_ALG_ID, Table 8): TPM_ALG_TDES 0x0003, TPM_ALG_AES 0x0006, TPM_ALG_SM4 0x0013, TPM_ALG_CAMELLIA 0x0026, TPM_ALG_NULL 0x0010.

    /// <summary>
    ///     Null algorithm
    /// </summary>
    /// <remarks>TCG TPM 2.0 library specification</remarks>
    TpmAlgNull = 0x0010
}
