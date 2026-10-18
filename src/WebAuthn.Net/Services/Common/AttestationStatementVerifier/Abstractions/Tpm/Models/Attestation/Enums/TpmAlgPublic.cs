namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation.Enums;

/// <summary>
///     <para>12.2.2 TPMI_ALG_PUBLIC, based on TPM_ALG_ID (UINT16) - TPM_ALG_RSA, TPM_ALG_KEYEDHASH, TPM_ALG_ECC, TPM_ALG_SYMCIPHER, TPM_ALG_MLDSA, TPM_ALG_HASH_MLDSA, TPM_ALG_MLKEM</para>
///     <para>Type of asymmetric algorithm with a public and private key, used by the TPM module for generating digital signatures in the process of WebAuthn ceremonies.</para>
///     <para>
///         Only TPM_ALG_RSA and TPM_ALG_ECC are members on purpose: the TPM-backed credential public key must match a COSE RSA or EC2 credentialPublicKey,
///         so a pubArea of any other object type of Table 225 (KEYEDHASH, SYMCIPHER, ML-DSA, ML-KEM) can never be a WebAuthn credential key and is rejected by the decoder
///         (mirroring TPMI_ALG_PUBLIC_Unmarshal of the reference implementation, TPM_RC_TYPE).
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
public enum TpmAlgPublic : ushort
{
    // 12.2.2 TPMI_ALG_PUBLIC
    // Table 225 — Definition of (TPM_ALG_ID) TPMI_ALG_PUBLIC Type
    // | Values             | Comments
    // | TPM_ALG_RSA        |
    // | TPM_ALG_KEYEDHASH  |
    // | TPM_ALG_ECC        |
    // | TPM_ALG_SYMCIPHER  |
    // | TPM_ALG_MLDSA      |
    // | TPM_ALG_HASH_MLDSA |
    // | TPM_ALG_MLKEM      |
    // | #TPM_RC_TYPE       | response code when a public type is not supported
    // Values (6.3 TPM_ALG_ID, Table 8): TPM_ALG_RSA 0x0001, TPM_ALG_KEYEDHASH 0x0008, TPM_ALG_ECC 0x0023, TPM_ALG_SYMCIPHER 0x0025, TPM_ALG_MLKEM 0x00A0, TPM_ALG_MLDSA 0x00A1, TPM_ALG_HASH_MLDSA 0x00A2.

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
