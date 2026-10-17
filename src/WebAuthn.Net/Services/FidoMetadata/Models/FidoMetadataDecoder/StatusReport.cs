using System;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder.Enums;

namespace WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder;

/// <summary>
///     Status Report
/// </summary>
/// <remarks>
///     <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#sctn-stat-rep">FIDO Metadata Service - StatusReport dictionary</a>
/// </remarks>
public class StatusReport
{
    /// <summary>
    ///     Constructs <see cref="StatusReport" />.
    /// </summary>
    /// <param name="status">Status of the authenticator. Additional fields MAY be set depending on this value.</param>
    /// <param name="effectiveDate">Date since when the status code was set, if applicable. If no date is given, the status is assumed to be effective while present.</param>
    /// <param name="authenticatorVersion">The "authenticatorVersion" (firmware version) that this status report relates to. In the case of FIDO_CERTIFIED* status values, the status applies to higher authenticatorVersions until there is a new statusReport.</param>
    /// <param name="batchCertificate">DER <a href="https://www.itu.int/rec/T-REC-X.690-200811-S">[ITU-X690-2008]</a> PKIX certificate value related to the current status, if applicable.</param>
    /// <param name="certificate">DER <a href="https://www.itu.int/rec/T-REC-X.690-200811-S">[ITU-X690-2008]</a> PKIX certificate value related to the current status, if applicable. This field will typically not be present if field "batchCertificate" is present.</param>
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
    /// <param name="sunsetDate">Date since when the status wil expire, if applicable. If no date is given, the status is assumed to not have a scheduled expiry.</param>
    /// <param name="fipsRevision">
    ///     The revision number of the FIPS 140 specification, e.g. "3" in the case of FIPS 140-3. This entry MUST be present if and only if the
    ///     <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#dom-statusreport-status">"status"</a> entry is one of FIPS140_CERTIFIED_L*.
    /// </param>
    /// <param name="fipsPhysicalSecurityLevel">
    ///     In the case the status represents a FIPS certification, this field contains the "physical security level" of the FIPS certification. This entry MUST be present if and only if the
    ///     <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#dom-statusreport-status">"status"</a> entry is one of FIPS140_CERTIFIED_L*. It MUST reflect the physical security level which might deviate from the overall level.
    /// </param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="status" /> contains a value that is not defined in <see cref="AuthenticatorStatus" /></exception>
    public StatusReport(
        AuthenticatorStatus status,
        DateTimeOffset? effectiveDate,
        ulong? authenticatorVersion,
        byte[]? batchCertificate,
        byte[]? certificate,
        string? url,
        string? certificationDescriptor,
        string? certificateNumber,
        string? certificationPolicyVersion,
        string[]? certificationProfiles,
        string? certificationRequirementsVersion,
        DateTimeOffset? sunsetDate,
        ulong? fipsRevision,
        ulong? fipsPhysicalSecurityLevel)
    {
        if (!Enum.IsDefined(status))
        {
            throw new ArgumentOutOfRangeException(nameof(status), "Value should be defined in the AuthenticatorStatus enum.");
        }

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
    public AuthenticatorStatus Status { get; }

    /// <summary>
    ///     Date since when the status code was set, if applicable. If no date is given, the status is assumed to be effective while present.
    /// </summary>
    public DateTimeOffset? EffectiveDate { get; }

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
    public ulong? AuthenticatorVersion { get; }

    /// <summary>
    ///     DER <a href="https://www.itu.int/rec/T-REC-X.690-200811-S">[ITU-X690-2008]</a> PKIX certificate value related to the current status, if applicable.
    /// </summary>
    /// <remarks>
    ///     As an example, this could be an Batch Attestation Certificate (see <a href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.1.1-ps-20260105.html">[FIDOMetadataStatement]</a>) related to a set of compromised authenticators (USER_KEY_REMOTE_COMPROMISE).
    /// </remarks>
    public byte[]? BatchCertificate { get; }

    /// <summary>
    ///     DER <a href="https://www.itu.int/rec/T-REC-X.690-200811-S">[ITU-X690-2008]</a> PKIX certificate value related to the current status, if applicable. This field will typically not be present if field "batchCertificate" is present.
    /// </summary>
    /// <remarks>
    ///     As an example, this could be an Attestation Root Certificate (see <a href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.1.1-ps-20260105.html">[FIDOMetadataStatement]</a>) related to a set of compromised authenticators (ATTESTATION_KEY_COMPROMISE).
    /// </remarks>
    public byte[]? Certificate { get; }

    /// <summary>
    ///     HTTPS URL where additional information may be found related to the current status, if applicable.
    /// </summary>
    /// <remarks>
    ///     For example a link to a web page describing an available firmware update in the case of status UPDATE_AVAILABLE, or a link to a description of an identified issue in the case of status USER_VERIFICATION_BYPASS.
    /// </remarks>
    public string? Url { get; }

    /// <summary>
    ///     Describes the externally visible aspects of the Authenticator Certification evaluation.
    /// </summary>
    /// <remarks>
    ///     For example it could state that the authenticator is a "SecurityKey based on a CC EAL 5 certified chip hardware".
    /// </remarks>
    public string? CertificationDescriptor { get; }

    /// <summary>
    ///     The unique identifier for the issued Certification.
    /// </summary>
    public string? CertificateNumber { get; }

    /// <summary>
    ///     The version of the Authenticator Certification Policy the implementation is Certified to, e.g. "1.0.0".
    /// </summary>
    public string? CertificationPolicyVersion { get; }

    /// <summary>
    ///     Each entry represents a supported certification profile. The supported profiles are defined in the active version of the "Authenticator Certification Policy" document. At the time of writing this specification, the supported profiles are: "consumer" and "enterprise".
    /// </summary>
    public string[]? CertificationProfiles { get; }

    /// <summary>
    ///     The Document Version of the Authenticator Security Requirements (DV) <a href="https://fidoalliance.org/specs/fido-security-requirements/fido-authenticator-security-requirements-v1.6-fd-20250312.html">[FIDOAuthenticatorSecurityRequirements]</a> the implementation is certified
    ///     to, e.g. "1.2.0".
    /// </summary>
    public string? CertificationRequirementsVersion { get; }

    /// <summary>
    ///     Date since when the status wil expire, if applicable. If no date is given, the status is assumed to not have a scheduled expiry.
    /// </summary>
    public DateTimeOffset? SunsetDate { get; }

    /// <summary>
    ///     The revision number of the FIPS 140 specification, e.g. "3" in the case of FIPS 140-3. This entry MUST be present if and only if the <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#dom-statusreport-status">"status"</a> entry is one
    ///     of
    ///     FIPS140_CERTIFIED_L*.
    /// </summary>
    public ulong? FipsRevision { get; }

    /// <summary>
    ///     In the case the status represents a FIPS certification, this field contains the "physical security level" of the FIPS certification. This entry MUST be present if and only if the
    ///     <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#dom-statusreport-status">"status"</a> entry is one of FIPS140_CERTIFIED_L*. It MUST reflect the physical security level which might deviate from the overall level.
    /// </summary>
    public ulong? FipsPhysicalSecurityLevel { get; }
}
