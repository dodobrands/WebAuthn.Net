using System;

namespace WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder;

/// <summary>
///     Metadata BLOB Payload Entry dictionary
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob-payload-entry-dictionary">FIDO Metadata Service - §3.1.1. Metadata BLOB Payload Entry dictionary</a>
///     </para>
/// </remarks>
public class MetadataBlobPayloadEntry
{
    /// <summary>
    ///     Constructs <see cref="MetadataBlobPayloadEntry" />.
    /// </summary>
    /// <param name="aaid">
    ///     The AAID of the authenticator this metadata BLOB payload entry relates to. See <a href="https://fidoalliance.org/specs/fido-uaf-v1.2-ps-20201020/fido-uaf-protocol-v1.2-ps-20201020.html#authenticator-attestation-id-aaid-typedef">[UAFProtocol]</a> for the definition of the
    ///     AAID structure. This field MUST be set if the authenticator implements FIDO UAF.
    /// </param>
    /// <param name="aaguid">
    ///     The Authenticator Attestation GUID. See <a href="https://fidoalliance.org/specs/fido-v2.0-ps-20150904/fido-key-attestation-v2.0-ps-20150904.html#attributes-2">[FIDOKeyAttestation]</a> for the definition of the AAGUID structure. This field MUST be set if the
    ///     authenticator implements FIDO2.
    /// </param>
    /// <param name="attestationCertificateKeyIdentifiers">
    ///     <para>
    ///         A list of the attestation certificate public key identifiers. This value MUST be calculated according to method 1 for computing the keyIdentifier as defined in <a href="https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.2">[RFC5280] section 4.2.1.2</a>.
    ///     </para>
    ///     <para>This field MUST be set if neither aaid nor aaguid are set. Setting this field implies that the attestation certificate(s) are dedicated to a single authenticator model.</para>
    /// </param>
    /// <param name="metadataStatement">The metadataStatement object as defined in <a href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#metadata-keys">[FIDOMetadataStatement]</a>.</param>
    /// <param name="biometricStatusReports">
    ///     Status of the FIDO Biometric Certification of one or more biometric components of the Authenticator <a href="https://fidoalliance.org/specs/biometric/requirements/Biometrics-Requirements-v2.0-fd-20201006.html">[FIDOBiometricsRequirements]</a>
    ///     .
    /// </param>
    /// <param name="statusReports">An array of status reports applicable to this authenticator.</param>
    /// <param name="timeOfLastStatusChange">Date since when the status report array was set to the current value.</param>
    /// <param name="rogueListUrl">URL of a list of rogue (i.e. untrusted) individual authenticators.</param>
    /// <param name="rogueListHash">
    ///     <para>base64url(string[1..512])</para>
    ///     <para>
    ///         The hash value computed over the Base64url encoding of the UTF-8 representation of the JSON encoded rogueList available at rogueListURL (with type rogueListEntry[]). The hash algorithm related to the signature algorithm specified in the JWTHeader (see
    ///         <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob">Metadata BLOB</a>) MUST be used.
    ///     </para>
    ///     <para>This hash value MUST be present and non-empty whenever rogueListURL is present.</para>
    /// </param>
    /// <exception cref="ArgumentNullException"><paramref name="attestationCertificateKeyIdentifiers" /> is <see langword="null" /> when <paramref name="aaid" /> and <paramref name="aaguid" /> are not set</exception>
    /// <exception cref="ArgumentNullException"><paramref name="rogueListHash" /> is <see langword="null" /> when <paramref name="rogueListUrl" /> is set</exception>
    public MetadataBlobPayloadEntry(
        string? aaid,
        Guid? aaguid,
        byte[][]? attestationCertificateKeyIdentifiers,
        MetadataStatement? metadataStatement,
        BiometricStatusReport[]? biometricStatusReports,
        StatusReport[] statusReports,
        DateTimeOffset timeOfLastStatusChange,
        string? rogueListUrl,
        string? rogueListHash)
    {
        Aaid = aaid;
        Aaguid = aaguid;
        if (aaid is null && !aaguid.HasValue && attestationCertificateKeyIdentifiers is null)
        {
            throw new ArgumentNullException(nameof(attestationCertificateKeyIdentifiers), "This field must be set if neither aaid nor aaguid are set");
        }

        AttestationCertificateKeyIdentifiers = attestationCertificateKeyIdentifiers;
        MetadataStatement = metadataStatement;
        BiometricStatusReports = biometricStatusReports;
        StatusReports = statusReports;
        TimeOfLastStatusChange = timeOfLastStatusChange;
        RogueListUrl = rogueListUrl;
        if (rogueListUrl is not null && rogueListHash is null)
        {
            throw new ArgumentNullException(nameof(rogueListHash), "This hash value MUST be present and non-empty whenever rogueListURL is present");
        }

        RogueListHash = rogueListHash;
    }

    /// <summary>
    ///     The AAID of the authenticator this metadata BLOB payload entry relates to. See <a href="https://fidoalliance.org/specs/fido-uaf-v1.2-ps-20201020/fido-uaf-protocol-v1.2-ps-20201020.html#authenticator-attestation-id-aaid-typedef">[UAFProtocol]</a> for the definition of the
    ///     AAID structure. This field MUST be set if the authenticator implements FIDO UAF.
    /// </summary>
    /// <remarks>
    ///     FIDO UAF authenticators support AAID, but they don't support AAGUID.
    /// </remarks>
    public string? Aaid { get; }

    /// <summary>
    ///     The Authenticator Attestation GUID. See <a href="https://fidoalliance.org/specs/fido-v2.0-ps-20150904/fido-key-attestation-v2.0-ps-20150904.html#attributes-2">[FIDOKeyAttestation]</a> for the definition of the AAGUID structure. This field MUST be set if the authenticator
    ///     implements FIDO2.
    /// </summary>
    /// <remarks>
    ///     FIDO2 authenticators support AAGUID, but they don't support AAID.
    /// </remarks>
    public Guid? Aaguid { get; }

    /// <summary>
    ///     <para>
    ///         A list of the attestation certificate public key identifiers. This value MUST be calculated according to method 1 for computing the keyIdentifier as defined in <a href="https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.2">[RFC5280] section 4.2.1.2</a>.
    ///     </para>
    ///     <para>This field MUST be set if neither aaid nor aaguid are set. Setting this field implies that the attestation certificate(s) are dedicated to a single authenticator model.</para>
    /// </summary>
    /// <remarks>
    ///     FIDO U2F authenticators do not support AAID nor AAGUID, but they use attestation certificates dedicated to a single authenticator model.
    /// </remarks>
    public byte[][]? AttestationCertificateKeyIdentifiers { get; }

    /// <summary>
    ///     The metadataStatement object as defined in <a href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#metadata-keys">[FIDOMetadataStatement]</a>.
    /// </summary>
    public MetadataStatement? MetadataStatement { get; }

    /// <summary>
    ///     Status of the FIDO Biometric Certification of one or more biometric components of the Authenticator <a href="https://fidoalliance.org/specs/biometric/requirements/Biometrics-Requirements-v2.0-fd-20201006.html">[FIDOBiometricsRequirements]</a>.
    /// </summary>
    public BiometricStatusReport[]? BiometricStatusReports { get; }

    /// <summary>
    ///     An array of status reports applicable to this authenticator.
    /// </summary>
    public StatusReport[] StatusReports { get; }

    /// <summary>
    ///     Date since when the status report array was set to the current value.
    /// </summary>
    public DateTimeOffset TimeOfLastStatusChange { get; }

    /// <summary>
    ///     URL of a list of rogue (i.e. untrusted) individual authenticators.
    /// </summary>
    public string? RogueListUrl { get; }

    /// <summary>
    ///     <para>base64url(string[1..512])</para>
    ///     <para>
    ///         The hash value computed over the Base64url encoding of the UTF-8 representation of the JSON encoded rogueList available at rogueListURL (with type rogueListEntry[]). The hash algorithm related to the signature algorithm specified in the JWTHeader (see
    ///         <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob">Metadata BLOB</a>) MUST be used.
    ///     </para>
    ///     <para>This hash value MUST be present and non-empty whenever rogueListURL is present.</para>
    /// </summary>
    public string? RogueListHash { get; }
}
