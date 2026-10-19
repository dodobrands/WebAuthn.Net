namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation.Enums;

/// <summary>
///     <para>11.2.5.4 TPMI_ALG_ECC_SCHEME, based on TPM_ALG_ID (UINT16) - TPM_ALG_ECDSA, TPM_ALG_ECDAA, TPM_ALG_SM2, TPM_ALG_ECSCHNORR, TPM_ALG_EDDSA, TPM_ALG_HASH_EDDSA, TPM_ALG_ECDH, TPM_ALG_ECMQV, +TPM_ALG_NULL</para>
///     <para>
///         The members are the wire-format vocabulary of TPMI_ALG_ECC_SCHEME (Table 200).
///         Which of them is acceptable for a given key depends on the key's sign/decrypt/restricted attributes (Table 229, reference SchemeChecks); the decoder applies those rules.
///         <see cref="TpmAlgEddsa" /> and <see cref="TpmAlgHashEddsa" /> are always rejected by the decoder: they are defined only for the Edwards curves, which <see cref="TpmiEccCurve" /> does not include.
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
public enum TpmiAlgEccScheme : ushort
{
    // 11.2.5.4 TPMI_ALG_ECC_SCHEME
    // Table 200 — Definition of (TPM_ALG_ID) {ECC} TPMI_ALG_ECC_SCHEME Type
    // | Values             | Comments
    // | TPM_ALG_ECDSA      |
    // | TPM_ALG_ECDAA      |
    // | TPM_ALG_SM2        |
    // | TPM_ALG_ECSCHNORR  |
    // | TPM_ALG_EDDSA      |
    // | TPM_ALG_HASH_EDDSA |
    // | TPM_ALG_ECDH       |
    // | TPM_ALG_SM2        |
    // | TPM_ALG_ECMQV      |
    // | +TPM_ALG_NULL      |
    // | #TPM_RC_SCHEME     |

    /// <summary>
    ///     Null algorithm
    /// </summary>
    /// <remarks>
    ///     <para>TPM_ALG_NULL</para>
    ///     <para>TCG TPM 2.0 library specification</para>
    /// </remarks>
    TpmAlgNull = 0x0010,

    /// <summary>
    ///     Signature algorithm using elliptic curve cryptography (ECC) (Non-deterministic ECDSA)
    /// </summary>
    /// <remarks>
    ///     <para>TPM_ALG_ECDSA</para>
    ///     <para>ISO/IEC 14888-3</para>
    /// </remarks>
    TpmAlgEcdsa = 0x0018,

    /// <summary>
    ///     <para>Elliptic Curve Diffie-Hellman</para>
    ///     <para>
    ///         Based on context, this can be one of:
    ///         <list type="bullet">
    ///             <item>"Elliptic Curve Cryptography Cofactor Diffie-Hellman (ECC CDH) Primitive" defined in 5.7.1.2 of SP 800-56A</item>
    ///             <item>X25519 or X448 as defined in clause 5 of RFC 7748</item>
    ///         </list>
    ///     </para>
    /// </summary>
    /// <remarks>
    ///     <para>TPM_ALG_ECDH</para>
    ///     <para>NIST SP 800-56A</para>
    ///     <para>IETF RFC 7748</para>
    /// </remarks>
    TpmAlgEcdh = 0x0019,

    /// <summary>
    ///     Elliptic-curve based, anonymous signing scheme
    /// </summary>
    /// <remarks>
    ///     <para>TPM_ALG_ECDAA</para>
    ///     <para>TCG TPM 2.0 library specification</para>
    /// </remarks>
    TpmAlgEcdaa = 0x001A,

    /// <summary>
    ///     SM2 - depending on context, either an elliptic-curve based signature algorithm, an encryption scheme or a key exchange protocol
    /// </summary>
    /// <remarks>
    ///     <para>TPM_ALG_SM2</para>
    ///     <para>GB/T 32918.1-2016</para>
    ///     <para>GB/T 32918.2-2016</para>
    ///     <para>GB/T 32918.3-2016</para>
    ///     <para>GB/T 32918.4-2016</para>
    ///     <para>GB/T 32918.5-2017</para>
    /// </remarks>
    TpmAlgSm2 = 0x001B,

    /// <summary>
    ///     Elliptic-curve based Schnorr signature
    /// </summary>
    /// <remarks>
    ///     <para>TPM_ALG_ECSCHNORR</para>
    ///     <para>TCG TPM 2.0 library specification</para>
    /// </remarks>
    TpmAlgEcschnorr = 0x001C,

    /// <summary>
    ///     "Full MQV, C(2e, 2s, ECC MQV)" defined in 6.1.1.4 of SP 800-56A
    /// </summary>
    /// <remarks>
    ///     <para>TPM_ALG_ECMQV</para>
    ///     <para>NIST SP 800-56A</para>
    /// </remarks>
    TpmAlgEcmqv = 0x001D,

    /// <summary>
    ///     Edwards-curve Digital Signature Algorithm (PureEdDSA)
    /// </summary>
    /// <remarks>
    ///     <para>TPM_ALG_EDDSA</para>
    ///     <para>RFC 8032</para>
    ///     <para>Defined only for the Edwards curves (TPM_ECC_CURVE_25519, TPM_ECC_CURVE_448), which <see cref="TpmiEccCurve" /> does not include; always rejected by the decoder.</para>
    /// </remarks>
    TpmAlgEddsa = 0x0060,

    /// <summary>
    ///     Edwards-curve Digital Signature Algorithm (HashEdDSA)
    /// </summary>
    /// <remarks>
    ///     <para>TPM_ALG_HASH_EDDSA</para>
    ///     <para>RFC 8032</para>
    ///     <para>Note: Earlier TCG specifications used the name TPM_ALG_EDDSA_PH.</para>
    ///     <para>Defined only for the Edwards curves (TPM_ECC_CURVE_25519, TPM_ECC_CURVE_448), which <see cref="TpmiEccCurve" /> does not include; always rejected by the decoder.</para>
    /// </remarks>
    TpmAlgHashEddsa = 0x0061
}
