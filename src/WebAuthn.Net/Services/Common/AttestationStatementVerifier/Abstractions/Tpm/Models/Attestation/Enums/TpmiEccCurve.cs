namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation.Enums;

/// <summary>
///     <para>11.2.5.5 TPMI_ECC_CURVE, based on TPM_ECC_CURVE (UINT16).</para>
///     <para>
///         Only the NIST curves P-256, P-384 and P-521 are members on purpose. The TPM-backed credential public key is compared with the COSE credentialPublicKey of the attested credential data,
///         and the COSE EC2 curves this library supports (RFC 9053, section 7.1.1) are exactly these three; a pubArea on any other curve of Table 201 (BN, SM2, Brainpool, Curve25519/448) can never match a credential key
///         and is rejected by the decoder, mirroring TPMI_ECC_CURVE_Unmarshal of the reference implementation (TPM_RC_CURVE for a curve the implementation does not support).
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
public enum TpmiEccCurve : ushort
{
    // 11.2.5.5 TPMI_ECC_CURVE
    // Table 201 — Definition of {ECC} (TPM_ECC_CURVE) TPMI_ECC_CURVE Type
    // | Parameter           | Value  | Comment
    // | +TPM_ECC_NONE       | 0x0000 |
    // | TPM_ECC_NIST_P192   | 0x0001 |
    // | TPM_ECC_NIST_P224   | 0x0002 |
    // | TPM_ECC_NIST_P256   | 0x0003 |
    // | TPM_ECC_NIST_P384   | 0x0004 |
    // | TPM_ECC_NIST_P521   | 0x0005 |
    // | TPM_ECC_BN_P256     | 0x0010 | curve to support ECDAA
    // | TPM_ECC_BN_P638     | 0x0011 | curve to support ECDAA
    // | TPM_ECC_SM2_P256    | 0x0020 |
    // | TPM_ECC_BP_P256_R1  | 0x0030 | Brainpool
    // | TPM_ECC_BP_P384_R1  | 0x0031 | Brainpool
    // | TPM_ECC_BP_P512_R1  | 0x0032 | Brainpool
    // | TPM_ECC_CURVE_25519 | 0x0040 | curve to support EdDSA
    // | TPM_ECC_CURVE_448   | 0x0041 | curve to support EdDSA
    // | #TPM_RC_CURVE       |        | error when curve is not supported
    // The numeric values are those of 6.4 TPM_ECC_CURVE (Table 9), a copy of the TCG Algorithm Registry.

    /// <summary>
    ///     TPM_ECC_NIST_P256 (32-byte coordinates)
    /// </summary>
    TpmEccNistP256 = 0x0003,

    /// <summary>
    ///     TPM_ECC_NIST_P384 (48-byte coordinates)
    /// </summary>
    TpmEccNistP384 = 0x0004,

    /// <summary>
    ///     TPM_ECC_NIST_P521 (66-byte coordinates)
    /// </summary>
    TpmEccNistP521 = 0x0005
}
