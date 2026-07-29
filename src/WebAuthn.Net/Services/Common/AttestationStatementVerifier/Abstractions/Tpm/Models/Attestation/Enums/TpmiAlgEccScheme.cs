namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation.Enums;

/// <summary>
///     <para>11.2.5.4 TPMI_ALG_ECC_SCHEME, based on TPM_ALG_ID (UINT16) - TPM_ALG_!ALG.ax,TPM_ALG_!ALG.am, +TPM_ALG_NULL</para>
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library</a>
///     </para>
///     <para>
///         <a href="https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-2-Structures.pdf">TPM 2.0 Library - Part 2: Structures, Family "2.0", Level 00 Revision 01.59, November 8, 2019</a>
///     </para>
/// </remarks>
public enum TpmiAlgEccScheme : ushort
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
    /// Signature algorithm using elliptic curve cryptography (ECC) (Non-deterministic ECDSA)
    /// </summary>
    /// <remarks>
    /// <para>TPM_ALG_ECDSA</para>
    /// <para>ISO/IEC 14888-3</para>
    /// </remarks>
    TpmAlgEcdsa = 0x0018,

    /// <summary>
    /// Elliptic-curve based, anonymous signing scheme
    /// </summary>
    /// <remarks>
    /// <para>TPM_ALG_ECDAA</para>
    /// <para>TCG TPM 2.0 library specification</para>
    /// </remarks>
    TpmAlgEcdaa = 0x001A,

    /// <summary>
    /// Depending on context, either an elliptic-curve based signature algorithm, an encryption scheme or a key exchange protocol
    /// </summary>
    /// <remarks>
    /// <para>TPM_ALG_SM2</para>
    /// <para>GB/T 32918.1-2016</para>
    /// <para>GB/T 32918.2-2016</para>
    /// <para>GB/T 32918.3-2016</para>
    /// <para>GB/T 32918.4-2016</para>
    /// <para>GB/T 32918.5-2017</para>
    /// </remarks>
    TpmAlgSm2 = 0x001B,

    /// <summary>
    /// Elliptic-curve based Schnorr signature
    /// </summary>
    /// <remarks>
    /// <para>TPM_ALG_ECSCHNORR</para>
    /// <para>TCG TPM 2.0 library specification</para>
    /// </remarks>
    TpmAlgEcschnorr = 0x001C,

    /// <summary>
    /// Edwards-curve Digital Signature Algorithm (PureEdDSA)
    /// </summary>
    /// <remarks>
    /// <para>TPM_ALG_EDDSA</para>
    /// <para>RFC 8032</para>
    /// </remarks>
    TpmAlgEddsa = 0x0060,

    /// <summary>
    /// Edwards-curve Digital Signature Algorithm (HashEdDSA)
    /// </summary>
    /// <remarks>
    /// <para>TPM_ALG_EDDSA_PH</para>
    /// <para>RFC 8032</para>
    /// </remarks>
    TpmAlgEddsaPh = 0x0061,

    /// <summary>
    /// <para>Edwards-curve Digital Signature Algorithm (HashEdDSA)</para>
    /// <para>
    /// Based on context, this can be one of:
    ///     <list type="bullet">
    ///         <item>Elliptic Curve Cryptography Cofactor Diffie-Hellman (ECC CDH) Primitive" defined in 5.7.1.2 of SP 800-56A</item>
    ///         <item>X25519 or X448 as defined in clause 5 of RFC 7748</item>
    ///     </list>
    /// </para>
    /// </summary>
    /// <remarks>
    /// <para>TPM_ALG_ECDH</para>
    /// <para>NIST SP 800-56A</para>
    /// <para>IETF RFC 7748</para>
    /// </remarks>
    TpmAlgEcdh = 0x0019,

    /// <summary>
    /// Full MQV, C(2e, 2s, ECC MQV)” defined in 6.1.1.4
    /// </summary>
    /// <remarks>
    /// <para>TPM_ALG_ECMQV</para>
    /// <para>NIST SP 800-56A</para>
    /// </remarks>
    TpmAlgEcmqv = 0x001D
}
