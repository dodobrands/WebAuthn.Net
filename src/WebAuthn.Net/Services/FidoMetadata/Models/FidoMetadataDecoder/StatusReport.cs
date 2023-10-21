using System;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder.Enums;

namespace WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder;

/// <summary>
///     StatusReport dictionary
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#statusreport-dictionary">FIDO Metadata Service - §3.1.3. StatusReport dictionary</a>
///     </para>
/// </remarks>
public class StatusReport
{
    /// <summary>
    ///     Constructs <see cref="StatusReport" />.
    /// </summary>
    /// <param name="status">Status of the authenticator. Additional fields MAY be set depending on this value.</param>
    /// <param name="effectiveDate">Date since when the status code was set, if applicable. If no date is given, the status is assumed to be effective while present.</param>
    /// <param name="authenticatorVersion">The authenticatorVersion that this status report relates to. In the case of FIDO_CERTIFIED* status values, the status applies to higher authenticatorVersions until there is a new statusReport.</param>
    /// <param name="certificate">Certificate value related to the current status, if applicable.</param>
    /// <param name="url">HTTPS URL where additional information may be found related to the current status, if applicable.</param>
    /// <param name="certificationDescriptor">Describes the externally visible aspects of the Authenticator Certification evaluation.</param>
    /// <param name="certificateNumber">The unique identifier for the issued Certification.</param>
    /// <param name="certificationPolicyVersion">The version of the Authenticator Certification Policy the implementation is Certified to, e.g. "1.0.0".</param>
    /// <param name="certificationRequirementsVersion">
    ///     The Document Version of the Authenticator Security Requirements (DV) <a href="https://fidoalliance.org/specs/fido-security-requirements/fido-authenticator-security-requirements-v1.4-fd-20201102.html">[FIDOAuthenticatorSecurityRequirements]</a> the implementation is certified
    ///     to, e.g. "1.2.0".
    /// </param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="status" /> contains a value that is not defined in <see cref="AuthenticatorStatus" /></exception>
    public StatusReport(
        AuthenticatorStatus status,
        DateTimeOffset? effectiveDate,
        ulong? authenticatorVersion,
        byte[]? certificate,
        string? url,
        string? certificationDescriptor,
        string? certificateNumber,
        string? certificationPolicyVersion,
        string? certificationRequirementsVersion)
    {
        if (!Enum.IsDefined(typeof(AuthenticatorStatus), status))
        {
            throw new ArgumentOutOfRangeException(nameof(status), "Value should be defined in the AuthenticatorStatus enum.");
        }

        Status = status;
        EffectiveDate = effectiveDate;
        AuthenticatorVersion = authenticatorVersion;
        Certificate = certificate;
        Url = url;
        CertificationDescriptor = certificationDescriptor;
        CertificateNumber = certificateNumber;
        CertificationPolicyVersion = certificationPolicyVersion;
        CertificationRequirementsVersion = certificationRequirementsVersion;
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
    ///     The authenticatorVersion that this status report relates to. In the case of FIDO_CERTIFIED* status values, the status applies to higher authenticatorVersions until there is a new statusReport.
    /// </summary>
    /// <remarks>
    ///     For example, if the status would be USER_VERIFICATION_BYPASS, the authenticatorVersion indicates the vulnerable firmware version of the authenticator. Similarly, if the status would be UPDATE_AVAILABLE, the authenticatorVersion indicates the updated firmware version that is
    ///     available now. If the status would be SELF_ASSERTION_SUBMITTED, the authenticatorVersion indicates the firmware version that the self assertion was based on.
    /// </remarks>
    public ulong? AuthenticatorVersion { get; }

    /// <summary>
    ///     Certificate value related to the current status, if applicable.
    /// </summary>
    /// <remarks>
    ///     As an example, this could be an Attestation Root Certificate (see <a href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html">[FIDOMetadataStatement]</a>) related to a set of compromised authenticators (ATTESTATION_KEY_COMPROMISE).
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
    ///     The Document Version of the Authenticator Security Requirements (DV) <a href="https://fidoalliance.org/specs/fido-security-requirements/fido-authenticator-security-requirements-v1.4-fd-20201102.html">[FIDOAuthenticatorSecurityRequirements]</a> the implementation is certified
    ///     to, e.g. "1.2.0".
    /// </summary>
    public string? CertificationRequirementsVersion { get; }
}
