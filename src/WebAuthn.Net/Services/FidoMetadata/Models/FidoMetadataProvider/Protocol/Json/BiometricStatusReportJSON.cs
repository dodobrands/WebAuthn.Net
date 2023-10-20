using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataProvider.Protocol.Json;

/// <summary>
///     BiometricStatusReport dictionary
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#biometricstatusreport-dictionary">FIDO Metadata Service - §3.1.2. BiometricStatusReport dictionary</a>
///     </para>
/// </remarks>
// ReSharper disable once InconsistentNaming
public class BiometricStatusReportJSON
{
    /// <summary>
    ///     Constructs <see cref="BiometricStatusReportJSON" />.
    /// </summary>
    /// <param name="certLevel">Achieved level of the biometric certification of this biometric component of the authenticator <a href="https://fidoalliance.org/specs/biometric/requirements/Biometrics-Requirements-v2.0-fd-20201006.html">[FIDOBiometricsRequirements]</a>.</param>
    /// <param name="modality">
    ///     A single a single USER_VERIFY short form case-sensitive string name constant, representing biometric modality. See section "User Verification Methods" in
    ///     <a href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#user-verification-methods">[FIDORegistry]</a> (e.g. "fingerprint_internal"). This value MUST NOT be empty and this value MUST correspond to one or more entries in field
    ///     userVerificationDetails in the related Metadata Statement <a href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html">[FIDOMetadataStatement]</a>. This value MUST represent a biometric modality.
    /// </param>
    /// <param name="effectiveDate">ISO-8601 formatted date since when the certLevel achieved, if applicable. If no date is given, the status is assumed to be effective while present.</param>
    /// <param name="certificationDescriptor">Describes the externally visible aspects of the Biometric Certification evaluation.</param>
    /// <param name="certificateNumber">The unique identifier for the issued Biometric Certification.</param>
    /// <param name="certificationPolicyVersion">The version of the Biometric Certification Policy the implementation is Certified to, e.g. "1.0.0".</param>
    /// <param name="certificationRequirementsVersion">
    ///     The version of the Biometric Requirements <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#biblio-fidobiometricsrequirements">[FIDOBiometricsRequirements]</a> the implementation is certified to, e.g. "1.0.0".
    /// </param>
    [JsonConstructor]
    public BiometricStatusReportJSON(
        ushort certLevel,
        string modality,
        string? effectiveDate,
        string? certificationDescriptor,
        string? certificateNumber,
        string? certificationPolicyVersion,
        string? certificationRequirementsVersion)
    {
        CertLevel = certLevel;
        Modality = modality;
        EffectiveDate = effectiveDate;
        CertificationDescriptor = certificationDescriptor;
        CertificateNumber = certificateNumber;
        CertificationPolicyVersion = certificationPolicyVersion;
        CertificationRequirementsVersion = certificationRequirementsVersion;
    }

    /// <summary>
    ///     Achieved level of the biometric certification of this biometric component of the authenticator <a href="https://fidoalliance.org/specs/biometric/requirements/Biometrics-Requirements-v2.0-fd-20201006.html">[FIDOBiometricsRequirements]</a>.
    /// </summary>
    [JsonPropertyName("certLevel")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public ushort CertLevel { get; }

    /// <summary>
    ///     A single a single USER_VERIFY short form case-sensitive string name constant, representing biometric modality. See section "User Verification Methods" in
    ///     <a href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#user-verification-methods">[FIDORegistry]</a> (e.g. "fingerprint_internal"). This value MUST NOT be empty and this value MUST correspond to one or more entries in field
    ///     userVerificationDetails in the related Metadata Statement <a href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html">[FIDOMetadataStatement]</a>. This value MUST represent a biometric modality.
    /// </summary>
    /// <remarks>
    ///     For example use USER_VERIFY_FINGERPRINT for the fingerprint based biometric component. In this case the related Metadata Statement must also claim fingerprint as one of the user verification methods.
    /// </remarks>
    [JsonPropertyName("modality")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string Modality { get; }

    /// <summary>
    ///     ISO-8601 formatted date since when the certLevel achieved, if applicable. If no date is given, the status is assumed to be effective while present.
    /// </summary>
    [JsonPropertyName("effectiveDate")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string? EffectiveDate { get; }

    /// <summary>
    ///     Describes the externally visible aspects of the Biometric Certification evaluation.
    /// </summary>
    /// <remarks>
    ///     For example it could state that the "biometric component is implemented OnChip - keeping biometric data inside the chip only.".
    /// </remarks>
    [JsonPropertyName("certificationDescriptor")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string? CertificationDescriptor { get; }

    /// <summary>
    ///     The unique identifier for the issued Biometric Certification.
    /// </summary>
    [JsonPropertyName("certificateNumber")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string? CertificateNumber { get; }

    /// <summary>
    ///     The version of the Biometric Certification Policy the implementation is Certified to, e.g. "1.0.0".
    /// </summary>
    [JsonPropertyName("certificationPolicyVersion")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string? CertificationPolicyVersion { get; }

    /// <summary>
    ///     The version of the Biometric Requirements <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#biblio-fidobiometricsrequirements">[FIDOBiometricsRequirements]</a> the implementation is certified to, e.g. "1.0.0".
    /// </summary>
    [JsonPropertyName("certificationRequirementsVersion")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string? CertificationRequirementsVersion { get; }
}
