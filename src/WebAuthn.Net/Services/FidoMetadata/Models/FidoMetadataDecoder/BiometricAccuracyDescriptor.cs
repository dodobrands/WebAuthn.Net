namespace WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder;

/// <summary>
///     BiometricAccuracyDescriptor dictionary
/// </summary>
/// <remarks>
///     <a href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.1.1-ps-20260105.html#sctn-type-bad">FIDO Metadata Statement - BiometricAccuracyDescriptor dictionary</a>
/// </remarks>
public class BiometricAccuracyDescriptor
{
    /// <summary>
    ///     Constructs <see cref="BiometricAccuracyDescriptor" />.
    /// </summary>
    /// <param name="selfAttestedFrr">
    ///     <para>
    ///         The false rejection rate <a href="https://www.iso.org/standard/73515.html">[ISOIEC-19795-1]</a> for a single template, i.e. the percentage of verification transactions with truthful claims of identity that are incorrectly denied. For example a FRR of 10% would be
    ///         encoded as 0.1.
    ///     </para>
    ///     <para>
    ///         This value is self attested and, if the authenticator passed biometric certification, the data is an independently verified FRR as measured when meeting the FRR target specified in the biometric certification requirements
    ///         <a href="https://fidoalliance.org/specs/biometric/requirements/Biometrics-Requirements-v5.0-rd02-20260901.html">[FIDOBiometricsRequirements]</a> for the indicated biometric certification level (see certLevel in related biometricStatusReport as specified in
    ///         <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#dom-biometricstatusreport-certlevel">[FIDOMetadataService]</a>).
    ///     </para>
    /// </param>
    /// <param name="selfAttestedFar">
    ///     <para>
    ///         The false acceptance rate <a href="https://www.iso.org/standard/73515.html">[ISOIEC-19795-1]</a> for a single template, i.e. the percentage of verification transactions with wrongful claims of identity that are incorrectly confirmed. For example a FAR of 0.002% would
    ///         be encoded as 0.00002.
    ///     </para>
    ///     <para>
    ///         This value is self attested and, if the authenticator passed biometric certification, the data is an independently verified FAR specified in the biometric certification requirements
    ///         <a href="https://fidoalliance.org/specs/biometric/requirements/Biometrics-Requirements-v5.0-rd02-20260901.html">[FIDOBiometricsRequirements]</a> for the indicated biomeric certification level (see certLevel in related biometricStatusReport as specified in
    ///         <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#dom-biometricstatusreport-certlevel">[FIDOMetadataService]</a>).
    ///     </para>
    /// </param>
    /// <param name="iaparThreshold">
    ///     <para>
    ///         Impostor Attack Presentation Accept Rate (IAPAR) is the proportion of impostor attack presentations using the same presentation attack instrument (PAI) species that result in accept
    ///         <a href="https://www.iso.org/obp/ui/#iso:std:iso-iec:30107:-3:ed-1:v1:en">[isoiec-30107-3]</a>. For biometric certification requirements
    ///         <a href="https://fidoalliance.org/specs/biometric/requirements/Biometrics-Requirements-v5.0-rd02-20260901.html">[FIDOBiometricsRequirements]</a>, certification can be achieved for an IAPAR threshold of less than 7% OR less than 15% for each of the PAI species tested.
    ///     </para>
    ///     <para>If the authenticator did not pass biometric certification, vendor can submit any number, but this number has not been validated for biometric performance requirements.</para>
    /// </param>
    /// <param name="maxTemplates">
    ///     <para>Maximum number of alternative templates from different fingers allowed (for other modalities, multiple parts of the body that can be used interchangeably), e.g. 3 if the user is allowed to enroll up to 3 different fingers to a fingerprint based authenticator.</para>
    ///     <para>
    ///         If the authenticator passed biometric certification this value defaults to 1. For maxTemplates greater than one, it SHALL be independently verified to ensure FAR meets biometric performance requirements of certLevel (of the related biometricStatusReport as specified in
    ///         <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#dom-biometricstatusreport-certlevel">[FIDOMetadataService]</a>).
    ///     </para>
    ///     <para>If the authenticator did not pass biometric certification, vendor can submit any number, but this number has not been validated for biometric performance requirements.</para>
    /// </param>
    /// <param name="maxRetries">Maximum number of false attempts before the authenticator will block this method (at least for some time). 0 means it will never block.</param>
    /// <param name="blockSlowdown">
    ///     Enforced minimum number of seconds wait time after blocking (e.g. due to forced reboot or similar). 0 means that this user verification method will be blocked either permanently or until an alternative user verification method succeeded. All
    ///     alternative user verification methods MUST be specified appropriately in the metadata in userVerificationDetails.
    /// </param>
    public BiometricAccuracyDescriptor(double? selfAttestedFrr, double? selfAttestedFar, double? iaparThreshold, ushort? maxTemplates, ushort? maxRetries, ushort? blockSlowdown)
    {
        SelfAttestedFrr = selfAttestedFrr;
        SelfAttestedFar = selfAttestedFar;
        IaparThreshold = iaparThreshold;
        MaxTemplates = maxTemplates;
        MaxRetries = maxRetries;
        BlockSlowdown = blockSlowdown;
    }

    /// <summary>
    ///     <para>
    ///         The false rejection rate <a href="https://www.iso.org/standard/73515.html">[ISOIEC-19795-1]</a> for a single template, i.e. the percentage of verification transactions with truthful claims of identity that are incorrectly denied. For example a FRR of 10% would be
    ///         encoded as 0.1.
    ///     </para>
    ///     <para>
    ///         This value is self attested and, if the authenticator passed biometric certification, the data is an independently verified FRR as measured when meeting the FRR target specified in the biometric certification requirements
    ///         <a href="https://fidoalliance.org/specs/biometric/requirements/Biometrics-Requirements-v5.0-rd02-20260901.html">[FIDOBiometricsRequirements]</a> for the indicated biometric certification level (see certLevel in related biometricStatusReport as specified in
    ///         <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#dom-biometricstatusreport-certlevel">[FIDOMetadataService]</a>).
    ///     </para>
    /// </summary>
    /// <remarks>
    ///     The false rejection rate is relevant for user convenience. Lower false rejection rates mean better convenience.
    /// </remarks>
    public double? SelfAttestedFrr { get; }

    /// <summary>
    ///     <para>
    ///         The false acceptance rate <a href="https://www.iso.org/standard/73515.html">[ISOIEC-19795-1]</a> for a single template, i.e. the percentage of verification transactions with wrongful claims of identity that are incorrectly confirmed. For example a FAR of 0.002% would
    ///         be encoded as 0.00002.
    ///     </para>
    ///     <para>
    ///         This value is self attested and, if the authenticator passed biometric certification, the data is an independently verified FAR specified in the biometric certification requirements
    ///         <a href="https://fidoalliance.org/specs/biometric/requirements/Biometrics-Requirements-v5.0-rd02-20260901.html">[FIDOBiometricsRequirements]</a> for the indicated biomeric certification level (see certLevel in related biometricStatusReport as specified in
    ///         <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#dom-biometricstatusreport-certlevel">[FIDOMetadataService]</a>).
    ///     </para>
    /// </summary>
    /// <remarks>
    ///     <para>The resulting FAR when all templates are used is approx. maxTemplates * FAR.</para>
    ///     <para>The false acceptance rate is relevant for the security. Lower false acceptance rates mean better security.</para>
    ///     <para>Only the live captured subjects are covered by this value - not the presentation of artefacts.</para>
    /// </remarks>
    public double? SelfAttestedFar { get; }

    /// <summary>
    ///     <para>
    ///         Impostor Attack Presentation Accept Rate (IAPAR) is the proportion of impostor attack presentations using the same presentation attack instrument (PAI) species that result in accept
    ///         <a href="https://www.iso.org/obp/ui/#iso:std:iso-iec:30107:-3:ed-1:v1:en">[isoiec-30107-3]</a>. For biometric certification requirements
    ///         <a href="https://fidoalliance.org/specs/biometric/requirements/Biometrics-Requirements-v5.0-rd02-20260901.html">[FIDOBiometricsRequirements]</a>, certification can be achieved for an IAPAR threshold of less than 7% OR less than 15% for each of the PAI species tested.
    ///     </para>
    ///     <para>If the authenticator did not pass biometric certification, vendor can submit any number, but this number has not been validated for biometric performance requirements.</para>
    /// </summary>
    public double? IaparThreshold { get; }

    /// <summary>
    ///     <para>Maximum number of alternative templates from different fingers allowed (for other modalities, multiple parts of the body that can be used interchangeably), e.g. 3 if the user is allowed to enroll up to 3 different fingers to a fingerprint based authenticator.</para>
    ///     <para>
    ///         If the authenticator passed biometric certification this value defaults to 1. For maxTemplates greater than one, it SHALL be independently verified to ensure FAR meets biometric performance requirements of certLevel (of the related biometricStatusReport as specified in
    ///         <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#dom-biometricstatusreport-certlevel">[FIDOMetadataService]</a>).
    ///     </para>
    ///     <para>If the authenticator did not pass biometric certification, vendor can submit any number, but this number has not been validated for biometric performance requirements.</para>
    /// </summary>
    public ushort? MaxTemplates { get; }

    /// <summary>
    ///     Maximum number of false attempts before the authenticator will block this method (at least for some time). 0 means it will never block.
    /// </summary>
    public ushort? MaxRetries { get; }

    /// <summary>
    ///     Enforced minimum number of seconds wait time after blocking (e.g. due to forced reboot or similar). 0 means that this user verification method will be blocked either permanently or until an alternative user verification method succeeded. All alternative user verification
    ///     methods MUST be specified appropriately in the metadata in userVerificationDetails.
    /// </summary>
    public ushort? BlockSlowdown { get; }
}
