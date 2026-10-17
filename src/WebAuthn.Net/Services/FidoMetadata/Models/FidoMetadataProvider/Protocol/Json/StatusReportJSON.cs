using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataProvider.Protocol.Json;

/// <summary>
///     Status Report
/// </summary>
/// <remarks>
///     <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#sctn-stat-rep">FIDO Metadata Service - StatusReport dictionary</a>
/// </remarks>
// ReSharper disable once InconsistentNaming
public class StatusReportJSON
{
    /// <summary>
    ///     Constructs <see cref="StatusReportJSON" />.
    /// </summary>
    /// <param name="status">Status of the authenticator. Additional fields MAY be set depending on this value.</param>
    /// <param name="effectiveDate">ISO-8601 formatted date since when the status code was set, if applicable. If no date is given, the status is assumed to be effective while present.</param>
    /// <param name="authenticatorVersion">The "authenticatorVersion" (firmware version) that this status report relates to. In the case of FIDO_CERTIFIED* status values, the status applies to higher authenticatorVersions until there is a new statusReport.</param>
    /// <param name="batchCertificate">Base64-encoded <a href="https://www.rfc-editor.org/rfc/rfc4648.html">[RFC4648]</a> (not base64url!) DER <a href="https://www.itu.int/rec/T-REC-X.690-200811-S">[ITU-X690-2008]</a> PKIX certificate value related to the current status, if applicable.</param>
    /// <param name="certificate">
    ///     Base64-encoded <a href="https://www.rfc-editor.org/rfc/rfc4648.html">[RFC4648]</a> (not base64url!) DER <a href="https://www.itu.int/rec/T-REC-X.690-200811-S">[ITU-X690-2008]</a> PKIX certificate value related to the current status, if applicable. This
    ///     field will typically not be present if field "batchCertificate" is present.
    /// </param>
    /// <param name="url">HTTPS URL where additional information may be found related to the current status, if applicable.</param>
    /// <param name="certificationDescriptor">Describes the externally visible aspects of the Authenticator Certification evaluation.</param>
    /// <param name="certificateNumber">The unique identifier for the issued Certification.</param>
    /// <param name="certificationPolicyVersion">The version of the Authenticator Certification Policy the implementation is Certified to, e.g. "1.0.0".</param>
    /// <param name="certificationProfiles">
    ///     Each entry represents a supported certification profile. The supported profiles are defined in the active version of the "Authenticator Certification Policy" document. At the time of writing this specification, the supported profiles are:
    ///     "consumer" and "enterprise".
    /// </param>
    /// <param name="certificationRequirementsVersion">
    ///     The Document Version of the Authenticator Security Requirements (DV) <a href="https://fidoalliance.org/specs/fido-security-requirements/fido-authenticator-security-requirements-v1.6-fd-20250312.html">[FIDOAuthenticatorSecurityRequirements]</a> the implementation is certified
    ///     to, e.g. "1.2.0".
    /// </param>
    /// <param name="sunsetDate">ISO-8601 formatted date since when the status wil expire, if applicable. If no date is given, the status is assumed to not have a scheduled expiry.</param>
    /// <param name="fipsRevision">
    ///     The revision number of the FIPS 140 specification, e.g. "3" in the case of FIPS 140-3. This entry MUST be present if and only if the
    ///     <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#dom-statusreport-status">"status"</a> entry is one of FIPS140_CERTIFIED_L*.
    /// </param>
    /// <param name="fipsPhysicalSecurityLevel">
    ///     In the case the status represents a FIPS certification, this field contains the "physical security level" of the FIPS certification. This entry MUST be present if and only if the
    ///     <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#dom-statusreport-status">"status"</a> entry is one of FIPS140_CERTIFIED_L*. It MUST reflect the physical security level which might deviate from the overall level.
    /// </param>
    [JsonConstructor]
    public StatusReportJSON(
        string status,
        string? effectiveDate,
        ulong? authenticatorVersion,
        string? batchCertificate,
        string? certificate,
        string? url,
        string? certificationDescriptor,
        string? certificateNumber,
        string? certificationPolicyVersion,
        string[]? certificationProfiles,
        string? certificationRequirementsVersion,
        string? sunsetDate,
        ulong? fipsRevision,
        ulong? fipsPhysicalSecurityLevel)
    {
        Status = status;
        EffectiveDate = effectiveDate;
        AuthenticatorVersion = authenticatorVersion;
        BatchCertificate = batchCertificate;
        Certificate = certificate;
        Url = url;
        CertificationDescriptor = certificationDescriptor;
        CertificateNumber = certificateNumber;
        CertificationPolicyVersion = certificationPolicyVersion;
        CertificationProfiles = certificationProfiles;
        CertificationRequirementsVersion = certificationRequirementsVersion;
        SunsetDate = sunsetDate;
        FipsRevision = fipsRevision;
        FipsPhysicalSecurityLevel = fipsPhysicalSecurityLevel;
    }

    /// <summary>
    ///     Status of the authenticator. Additional fields MAY be set depending on this value.
    /// </summary>
    [JsonPropertyName("status")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string Status { get; }

    /// <summary>
    ///     ISO-8601 formatted date since when the status code was set, if applicable. If no date is given, the status is assumed to be effective while present.
    /// </summary>
    [JsonPropertyName("effectiveDate")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string? EffectiveDate { get; }

    /// <summary>
    ///     The "authenticatorVersion" (firmware version) that this status report relates to. In the case of FIDO_CERTIFIED* status values, the status applies to higher authenticatorVersions until there is a new statusReport.
    /// </summary>
    /// <remarks>
    ///     <para>
    ///         For example, if the status would be USER_VERIFICATION_BYPASS, the authenticatorVersion indicates the vulnerable firmware version of the authenticator. Similarly, if the status would be UPDATE_AVAILABLE, the authenticatorVersion indicates the updated firmware version
    ///         that is available now. If the status would be SELF_ASSERTION_SUBMITTED, the authenticatorVersion indicates the firmware version that the self assertion was based on.
    ///     </para>
    ///     <para>The firmware version of the authenticator providing the attestation can be found in the attestation certificate in extension id-fido-gen-ce-fw-version (OID 1.3.6.1.4.1.45724.1.1.5).</para>
    /// </remarks>
    [JsonPropertyName("authenticatorVersion")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public ulong? AuthenticatorVersion { get; }

    /// <summary>
    ///     Base64-encoded <a href="https://www.rfc-editor.org/rfc/rfc4648.html">[RFC4648]</a> (not base64url!) DER <a href="https://www.itu.int/rec/T-REC-X.690-200811-S">[ITU-X690-2008]</a> PKIX certificate value related to the current status, if applicable.
    /// </summary>
    /// <remarks>
    ///     As an example, this could be an Batch Attestation Certificate (see <a href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.1.1-ps-20260105.html">[FIDOMetadataStatement]</a>) related to a set of compromised authenticators (USER_KEY_REMOTE_COMPROMISE).
    /// </remarks>
    [JsonPropertyName("batchCertificate")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string? BatchCertificate { get; }

    /// <summary>
    ///     Base64-encoded <a href="https://www.rfc-editor.org/rfc/rfc4648.html">[RFC4648]</a> (not base64url!) DER <a href="https://www.itu.int/rec/T-REC-X.690-200811-S">[ITU-X690-2008]</a> PKIX certificate value related to the current status, if applicable. This field will typically
    ///     not be present if field "batchCertificate" is present.
    /// </summary>
    /// <remarks>
    ///     As an example, this could be an Attestation Root Certificate (see <a href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.1.1-ps-20260105.html">[FIDOMetadataStatement]</a>) related to a set of compromised authenticators (ATTESTATION_KEY_COMPROMISE).
    /// </remarks>
    [JsonPropertyName("certificate")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string? Certificate { get; }

    /// <summary>
    ///     HTTPS URL where additional information may be found related to the current status, if applicable.
    /// </summary>
    /// <remarks>
    ///     For example a link to a web page describing an available firmware update in the case of status UPDATE_AVAILABLE, or a link to a description of an identified issue in the case of status USER_VERIFICATION_BYPASS.
    /// </remarks>
    [JsonPropertyName("url")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string? Url { get; }

    /// <summary>
    ///     Describes the externally visible aspects of the Authenticator Certification evaluation.
    /// </summary>
    /// <remarks>
    ///     For example it could state that the authenticator is a "SecurityKey based on a CC EAL 5 certified chip hardware".
    /// </remarks>
    [JsonPropertyName("certificationDescriptor")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string? CertificationDescriptor { get; }

    /// <summary>
    ///     The unique identifier for the issued Certification.
    /// </summary>
    [JsonPropertyName("certificateNumber")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string? CertificateNumber { get; }

    /// <summary>
    ///     The version of the Authenticator Certification Policy the implementation is Certified to, e.g. "1.0.0".
    /// </summary>
    [JsonPropertyName("certificationPolicyVersion")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string? CertificationPolicyVersion { get; }

    /// <summary>
    ///     Each entry represents a supported certification profile. The supported profiles are defined in the active version of the "Authenticator Certification Policy" document. At the time of writing this specification, the supported profiles are: "consumer" and "enterprise".
    /// </summary>
    [JsonPropertyName("certificationProfiles")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string[]? CertificationProfiles { get; }

    /// <summary>
    ///     The Document Version of the Authenticator Security Requirements (DV) <a href="https://fidoalliance.org/specs/fido-security-requirements/fido-authenticator-security-requirements-v1.6-fd-20250312.html">[FIDOAuthenticatorSecurityRequirements]</a> the implementation is certified
    ///     to, e.g. "1.2.0".
    /// </summary>
    [JsonPropertyName("certificationRequirementsVersion")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string? CertificationRequirementsVersion { get; }

    /// <summary>
    ///     ISO-8601 formatted date since when the status wil expire, if applicable. If no date is given, the status is assumed to not have a scheduled expiry.
    /// </summary>
    [JsonPropertyName("sunsetDate")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string? SunsetDate { get; }

    /// <summary>
    ///     The revision number of the FIPS 140 specification, e.g. "3" in the case of FIPS 140-3. This entry MUST be present if and only if the <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#dom-statusreport-status">"status"</a> entry is one
    ///     of
    ///     FIPS140_CERTIFIED_L*.
    /// </summary>
    [JsonPropertyName("fipsRevision")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public ulong? FipsRevision { get; }

    /// <summary>
    ///     In the case the status represents a FIPS certification, this field contains the "physical security level" of the FIPS certification. This entry MUST be present if and only if the
    ///     <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#dom-statusreport-status">"status"</a> entry is one of FIPS140_CERTIFIED_L*. It MUST reflect the physical security level which might deviate from the overall level.
    /// </summary>
    [JsonPropertyName("fipsPhysicalSecurityLevel")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public ulong? FipsPhysicalSecurityLevel { get; }
}
