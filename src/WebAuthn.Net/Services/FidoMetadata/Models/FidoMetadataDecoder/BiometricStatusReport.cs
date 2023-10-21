using System;
using System.Numerics;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder.Enums;

namespace WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder;

/// <summary>
///     BiometricStatusReport dictionary
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#biometricstatusreport-dictionary">FIDO Metadata Service - §3.1.2. BiometricStatusReport dictionary</a>
///     </para>
/// </remarks>
public class BiometricStatusReport
{
    /// <summary>
    ///     Constructs <see cref="BiometricStatusReport" />.
    /// </summary>
    /// <param name="certLevel">Achieved level of the biometric certification of this biometric component of the authenticator <a href="https://fidoalliance.org/specs/biometric/requirements/Biometrics-Requirements-v2.0-fd-20201006.html">[FIDOBiometricsRequirements]</a>.</param>
    /// <param name="modality">Single USER_VERIFY constant, representing biometric modality.</param>
    /// <param name="effectiveDate">Date since when the certLevel achieved, if applicable. If no date is given, the status is assumed to be effective while present.</param>
    /// <param name="certificationDescriptor">Describes the externally visible aspects of the Biometric Certification evaluation.</param>
    /// <param name="certificateNumber">The unique identifier for the issued Biometric Certification.</param>
    /// <param name="certificationPolicyVersion">The version of the Biometric Certification Policy the implementation is Certified to, e.g. "1.0.0".</param>
    /// <param name="certificationRequirementsVersion">
    ///     The version of the Biometric Requirements <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#biblio-fidobiometricsrequirements">[FIDOBiometricsRequirements]</a> the implementation is certified to, e.g. "1.0.0".
    /// </param>
    /// <exception cref="ArgumentException"><paramref name="modality" /> doesn't contain a single USER_VERIFY constant</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="modality" /> contains a value that is not defined in <see cref="UserVerificationMethod" /></exception>
    public BiometricStatusReport(
        ushort certLevel,
        UserVerificationMethod modality,
        DateTimeOffset? effectiveDate,
        string? certificationDescriptor,
        string? certificateNumber,
        string? certificationPolicyVersion,
        string? certificationRequirementsVersion)
    {
        // certLevel
        CertLevel = certLevel;

        // modality
        if (BitOperations.PopCount((uint) modality) != 1)
        {
            throw new ArgumentException("'modality' must contain a single USER_VERIFY constant, representing biometric modality", nameof(modality));
        }

        if (!Enum.IsDefined(typeof(UserVerificationMethod), modality))
        {
            throw new ArgumentOutOfRangeException(nameof(modality), "Value should be defined in the UserVerificationMethod enum.");
        }

        Modality = modality;

        // effectiveDate
        EffectiveDate = effectiveDate;

        // certificationDescriptor
        CertificationDescriptor = certificationDescriptor;

        // certificateNumber
        CertificateNumber = certificateNumber;

        // certificationPolicyVersion
        CertificationPolicyVersion = certificationPolicyVersion;

        // certificationRequirementsVersion
        CertificationRequirementsVersion = certificationRequirementsVersion;
    }

    /// <summary>
    ///     Achieved level of the biometric certification of this biometric component of the authenticator <a href="https://fidoalliance.org/specs/biometric/requirements/Biometrics-Requirements-v2.0-fd-20201006.html">[FIDOBiometricsRequirements]</a>.
    /// </summary>
    public ushort CertLevel { get; }

    /// <summary>
    ///     Single USER_VERIFY constant, representing biometric modality.
    /// </summary>
    public UserVerificationMethod Modality { get; }

    /// <summary>
    ///     Date since when the certLevel achieved, if applicable. If no date is given, the status is assumed to be effective while present.
    /// </summary>
    public DateTimeOffset? EffectiveDate { get; }

    /// <summary>
    ///     Describes the externally visible aspects of the Biometric Certification evaluation.
    /// </summary>
    /// <remarks>
    ///     For example it could state that the "biometric component is implemented OnChip - keeping biometric data inside the chip only.".
    /// </remarks>
    public string? CertificationDescriptor { get; }

    /// <summary>
    ///     The unique identifier for the issued Biometric Certification.
    /// </summary>
    public string? CertificateNumber { get; }

    /// <summary>
    ///     The version of the Biometric Certification Policy the implementation is Certified to, e.g. "1.0.0".
    /// </summary>
    public string? CertificationPolicyVersion { get; }

    /// <summary>
    ///     The version of the Biometric Requirements <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#biblio-fidobiometricsrequirements">[FIDOBiometricsRequirements]</a> the implementation is certified to, e.g. "1.0.0".
    /// </summary>
    public string? CertificationRequirementsVersion { get; }
}
