namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation.Enums;

/// <summary>
///     <para>11.2.4.1 TPMI_ALG_RSA_SCHEME, based on TPM_ALG_ID (UINT16) - TPM_ALG_RSASSA, TPM_ALG_RSAES, TPM_ALG_RSAPSS, TPM_ALG_OAEP, +TPM_ALG_NULL</para>
///     <para>
///         The members are the wire-format vocabulary of TPMI_ALG_RSA_SCHEME (Table 189).
///         Which of them is acceptable for a given key depends on the key's sign/decrypt/restricted attributes (Table 228, reference SchemeChecks); the decoder applies those rules.
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
public enum TpmiAlgRsaScheme : ushort
{
    // 11.2.4.1 TPMI_ALG_RSA_SCHEME
    // Table 189 — Definition of (TPM_ALG_ID) {RSA} TPMI_ALG_RSA_SCHEME Type
    // | Values         | Comments
    // | TPM_ALG_RSASSA |
    // | TPM_ALG_RSAES  |
    // | TPM_ALG_RSAPSS |
    // | TPM_ALG_OAEP   |
    // | +TPM_ALG_NULL  |
    // | #TPM_RC_VALUE  |

    /// <summary>
    ///     Null algorithm
    /// </summary>
    /// <remarks>
    /// <para>TPM_ALG_NULL</para>
    /// <para>TCG TPM 2.0 library specification</para>
    /// </remarks>
    TpmAlgNull = 0x0010,

    /// <summary>
    /// A signature algorithm defined in clause 8.2 (RSASSA-PKCS1-v1_5)
    /// </summary>
    /// <remarks>
    /// <para>TPM_ALG_RSASSA</para>
    /// <para>IETF RFC 8017</para>
    /// </remarks>
    TpmAlgRsassa = 0x0014,

    /// <summary>
    /// A padding algorithm defined in clause 7.2 (RSAES-PKCS1-v1_5)
    /// </summary>
    /// <remarks>
    /// <para>TPM_ALG_RSAES</para>
    /// <para>RFC 8017</para>
    /// </remarks>
    TpmAlgRsaes = 0x0015,

    /// <summary>
    /// A signature algorithm defined in clause 8.1 (RSASSA-PSS)
    /// </summary>
    /// <remarks>
    /// <para>TPM_ALG_RSAPSS</para>
    /// <para>IETF RFC 8017</para>
    /// </remarks>
    TpmAlgRsapss = 0x0016,

    /// <summary>
    /// A padding algorithm defined in clause 7.1 (RSAES_OAEP)
    /// </summary>
    /// <remarks>
    /// <para>TPM_ALG_OAEP</para>
    /// <para>RFC 8017</para>
    /// </remarks>
    TpmAlgOaep = 0x0017
}
