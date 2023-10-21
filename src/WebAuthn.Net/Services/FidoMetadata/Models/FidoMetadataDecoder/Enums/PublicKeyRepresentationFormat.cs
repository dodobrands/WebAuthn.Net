using System.Diagnostics.CodeAnalysis;
using System.Runtime.Serialization;

namespace WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder.Enums;

/// <summary>
///     Public Key Representation Format
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-ps-20220523.html#public-key-representation-formats">FIDO Registry of Predefined Values - §3.6.2 Public Key Representation Formats</a>
///     </para>
/// </remarks>
[SuppressMessage("ReSharper", "InconsistentNaming")]
public enum PublicKeyRepresentationFormat : ushort
{
    /// <summary>
    ///     Raw ANSI X9.62 formatted Elliptic Curve public key [SEC1].
    /// </summary>
    [EnumMember(Value = "ecc_x962_raw")]
    ALG_KEY_ECC_X962_RAW = 0x0100,

    /// <summary>
    ///     DER [ITU-X690-2008] encoded ANSI X.9.62 formatted SubjectPublicKeyInfo [RFC5480] specifying an elliptic curve public key.
    /// </summary>
    [EnumMember(Value = "ecc_x962_der")]
    ALG_KEY_ECC_X962_DER = 0x0101,

    /// <summary>
    ///     Raw encoded 2048-bit RSA public key [RFC3447].
    /// </summary>
    [EnumMember(Value = "rsa_2048_raw")]
    ALG_KEY_RSA_2048_RAW = 0x0102,

    /// <summary>
    ///     ASN.1 DER [ITU-X690-2008] encoded 2048-bit RSA [RFC3447] public key [RFC4055].
    /// </summary>
    [EnumMember(Value = "rsa_2048_der")]
    ALG_KEY_RSA_2048_DER = 0x0103,

    /// <summary>
    ///     COSE_Key format, as defined in Section 7 of [RFC8152]. This encoding includes its own field for indicating the public key algorithm.
    /// </summary>
    [EnumMember(Value = "cose")]
    ALG_KEY_COSE = 0x0104
}
