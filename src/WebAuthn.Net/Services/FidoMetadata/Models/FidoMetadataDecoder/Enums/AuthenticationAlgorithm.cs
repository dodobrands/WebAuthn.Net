using System.Diagnostics.CodeAnalysis;
using System.Runtime.Serialization;

namespace WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder.Enums;

/// <summary>
///     Authenticator Status
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-ps-20220523.html#authentication-algorithms">FIDO Registry of Predefined Values - §3.6.1 Authentication Algorithms</a>
///     </para>
/// </remarks>
[SuppressMessage("ReSharper", "InconsistentNaming")]
public enum AuthenticationAlgorithm : ushort
{
    /// <summary>
    ///     An ECDSA signature on the NIST secp256r1 curve which must have raw R and S buffers, encoded in big-endian order. This is the signature encoding as specified in [ECDSA-ANSI].
    /// </summary>
    [EnumMember(Value = "secp256r1_ecdsa_sha256_raw")]
    ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW = 0x0001,

    /// <summary>
    ///     DER [ITU-X690-2008] encoded ECDSA signature [RFC5480] on the NIST secp256r1 curve.
    /// </summary>
    [EnumMember(Value = "secp256r1_ecdsa_sha256_der")]
    ALG_SIGN_SECP256R1_ECDSA_SHA256_DER = 0x0002,

    /// <summary>
    ///     RSASSA-PSS [RFC3447] signature must have raw S buffers, encoded in big-endian order [RFC4055] [RFC4056].
    /// </summary>
    [EnumMember(Value = "rsassa_pss_sha256_raw")]
    ALG_SIGN_RSASSA_PSS_SHA256_RAW = 0x0003,

    /// <summary>
    ///     DER [ITU-X690-2008] encoded OCTET STRING (not BIT STRING!) containing the RSASSA-PSS [RFC3447] signature [RFC4055] [RFC4056].
    /// </summary>
    [EnumMember(Value = "rsassa_pss_sha256_der")]
    ALG_SIGN_RSASSA_PSS_SHA256_DER = 0x0004,

    /// <summary>
    ///     An ECDSA signature on the secp256k1 curve which must have raw R and S buffers, encoded in big-endian order.
    /// </summary>
    [EnumMember(Value = "secp256k1_ecdsa_sha256_raw")]
    ALG_SIGN_SECP256K1_ECDSA_SHA256_RAW = 0x0005,

    /// <summary>
    ///     DER [ITU-X690-2008] encoded ECDSA signature [RFC5480] on the secp256k1 curve.
    /// </summary>
    [EnumMember(Value = "secp256k1_ecdsa_sha256_der")]
    ALG_SIGN_SECP256K1_ECDSA_SHA256_DER = 0x0006,

    /// <summary>
    ///     Chinese SM2 elliptic curve based signature algorithm combined with SM3 hash algorithm [OSCCA-SM2][OSCCA-SM3]. We use the 256bit curve [OSCCA-SM2-curve-param].
    /// </summary>
    [EnumMember(Value = "sm2_sm3_raw")]
    ALG_SIGN_SM2_SM3_RAW = 0x0007,

    /// <summary>
    ///     This is the EMSA-PKCS1-v1_5 signature as defined in [RFC3447]. This means that the encoded message EM will be the input to the cryptographic signing algorithm RSASP1 as defined in [RFC3447]. The result s of RSASP1 is then encoded using function I2OSP to produce the raw
    ///     signature octets.
    /// </summary>
    [EnumMember(Value = "rsa_emsa_pkcs1_sha256_raw")]
    ALG_SIGN_RSA_EMSA_PKCS1_SHA256_RAW = 0x0008,

    /// <summary>
    ///     DER [ITU-X690-2008] encoded OCTET STRING (not BIT STRING!) containing the EMSA-PKCS1-v1_5 signature as defined in [RFC3447].
    /// </summary>
    [EnumMember(Value = "rsa_emsa_pkcs1_sha256_der")]
    ALG_SIGN_RSA_EMSA_PKCS1_SHA256_DER = 0x0009,

    /// <summary>
    ///     RSASSA-PSS [RFC3447] signature must have raw S buffers, encoded in big-endian order [RFC4055] [RFC4056].
    /// </summary>
    [EnumMember(Value = "rsassa_pss_sha384_raw")]
    ALG_SIGN_RSASSA_PSS_SHA384_RAW = 0x000A,

    /// <summary>
    ///     RSASSA-PSS [RFC3447] signature must have raw S buffers, encoded in big-endian order [RFC4055] [RFC4056].
    /// </summary>
    [EnumMember(Value = "rsassa_pss_sha512_raw")]
    ALG_SIGN_RSASSA_PSS_SHA512_RAW = 0x000B,

    /// <summary>
    ///     RSASSA-PKCS1-v1_5 [RFC3447] with SHA256(aka RS256) signature must have raw S buffers, encoded in big-endian order [RFC8017] [RFC4056].
    /// </summary>
    [EnumMember(Value = "rsassa_pkcsv15_sha256_raw")]
    ALG_SIGN_RSASSA_PKCSV15_SHA256_RAW = 0x000C,

    /// <summary>
    ///     RSASSA-PKCS1-v1_5 [RFC3447] with SHA384(aka RS384) signature must have raw S buffers, encoded in big-endian order [RFC8017] [RFC4056].
    /// </summary>
    [EnumMember(Value = "rsassa_pkcsv15_sha384_raw")]
    ALG_SIGN_RSASSA_PKCSV15_SHA384_RAW = 0x000D,

    /// <summary>
    ///     RSASSA-PKCS1-v1_5 [RFC3447] with SHA512(aka RS512) signature must have raw S buffers, encoded in big-endian order [RFC8017] [RFC4056].
    /// </summary>
    [EnumMember(Value = "rsassa_pkcsv15_sha512_raw")]
    ALG_SIGN_RSASSA_PKCSV15_SHA512_RAW = 0x000E,

    /// <summary>
    ///     RSASSA-PKCS1-v1_5 [RFC3447] with SHA1(aka RS1) signature must have raw S buffers, encoded in big-endian order [RFC8017] [RFC4056].
    /// </summary>
    [EnumMember(Value = "rsassa_pkcsv15_sha1_raw")]
    ALG_SIGN_RSASSA_PKCSV15_SHA1_RAW = 0x000F,

    /// <summary>
    ///     An ECDSA signature on the NIST secp384r1 curve with SHA384(aka: ES384) which must have raw R and S buffers, encoded in big-endian order. This is the signature encoding as specified in [ECDSA-ANSI].
    /// </summary>
    [EnumMember(Value = "secp384r1_ecdsa_sha384_raw")]
    ALG_SIGN_SECP384R1_ECDSA_SHA384_RAW = 0x0010,

    /// <summary>
    ///     An ECDSA signature on the NIST secp512r1 curve with SHA512(aka: ES512) which must have raw R and S buffers, encoded in big-endian order. This is the signature encoding as specified in [ECDSA-ANSI].
    /// </summary>
    [EnumMember(Value = "secp521r1_ecdsa_sha512_raw")]
    ALG_SIGN_SECP521R1_ECDSA_SHA512_RAW = 0x0011,

    /// <summary>
    ///     An EdDSA signature on the curve 25519, which must have raw R and S buffers, encoded in big-endian order. This is the signature encoding as specified in [RFC8032].
    /// </summary>
    [EnumMember(Value = "ed25519_eddsa_sha512_raw")]
    ALG_SIGN_ED25519_EDDSA_SHA512_RAW = 0x0012,

    /// <summary>
    ///     An EdDSA signature on the curve Ed448, which must have raw R and S buffers, encoded in big-endian order. This is the signature encoding as specified in [RFC8032].
    /// </summary>
    [EnumMember(Value = "ed448_eddsa_sha512_raw")]
    ALG_SIGN_ED448_EDDSA_SHA512_RAW = 0x0013
}
