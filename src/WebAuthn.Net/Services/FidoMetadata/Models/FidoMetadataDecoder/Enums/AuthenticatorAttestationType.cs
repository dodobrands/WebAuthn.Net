using System.Diagnostics.CodeAnalysis;
using System.Runtime.Serialization;

namespace WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder.Enums;

/// <summary>
///     Authenticator Attestation Type
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-ps-20220523.html#authenticator-attestation-types">FIDO Registry of Predefined Values - §3.7 Authenticator Attestation Types</a>
///     </para>
/// </remarks>
[SuppressMessage("ReSharper", "InconsistentNaming")]
public enum AuthenticatorAttestationType : ushort
{
    /// <summary>
    ///     Indicates full basic attestation, based on an attestation private key shared among a class of authenticators (e.g. same model). Authenticators must provide its attestation signature during the registration process for the same reason. The attestation trust anchor is shared
    ///     with FIDO Servers out of band (as part of the Metadata). This sharing process should be done according to [FIDOMetadataService].
    /// </summary>
    [EnumMember(Value = "basic_full")]
    ATTESTATION_BASIC_FULL = 0x3E07,

    /// <summary>
    ///     Just syntactically a Basic Attestation. The attestation object self-signed, i.e. it is signed using the UAuth.priv key, i.e. the key corresponding to the UAuth.pub key included in the attestation object. As a consequence it does not provide a cryptographic proof of the
    ///     security characteristics. But it is the best thing we can do if the authenticator is not able to have an attestation private key.
    /// </summary>
    [EnumMember(Value = "basic_surrogate")]
    ATTESTATION_BASIC_SURROGATE = 0x3E08,

    /// <summary>
    ///     Indicates use of elliptic curve based direct anonymous attestation as defined in [FIDOEcdaaAlgorithm]. Support for this attestation type is optional at this time. It might be required by FIDO Certification.
    /// </summary>
    [EnumMember(Value = "ecdaa")]
    ATTESTATION_ECDAA = 0x3E09,

    /// <summary>
    ///     Indicates PrivacyCA attestation as defined in [TCG-CMCProfile-AIKCertEnroll]. Support for this attestation type is optional at this time. It might be required by FIDO Certification.
    /// </summary>
    [EnumMember(Value = "attca")]
    ATTESTATION_ATTCA = 0x3E0A,

    /// <summary>
    ///     In this case, the authenticator uses an Anonymization CA which dynamically generates per-credential attestation certificates such that the attestation statements presented to Relying Parties do not provide uniquely identifiable information, e.g., that might be used for
    ///     tracking purposes. The applicable [WebAuthn] attestation formats "fmt" are Google SafetyNet Attestation "android-safetynet", Android Keystore Attestation "android-key", Apple Anonymous Attestation "apple", and Apple Application Attestation "apple-appattest".
    /// </summary>
    [EnumMember(Value = "anonca")]
    ATTESTATION_ANONCA = 0x3E0C,

    /// <summary>
    ///     Indicates absence of attestation.
    /// </summary>
    [EnumMember(Value = "none")]
    ATTESTATION_NONE = 0x3E0B
}
