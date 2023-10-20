using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataProvider.Protocol.Json;

/// <summary>
///     Metadata BLOB Payload Entry dictionary
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob-payload-entry-dictionary">FIDO Metadata Service - §3.1.1. Metadata BLOB Payload Entry dictionary</a>
///     </para>
/// </remarks>
// ReSharper disable once InconsistentNaming
public class MetadataBLOBPayloadEntryJSON
{
    /// <summary>
    ///     Constructs <see cref="MetadataBLOBPayloadEntryJSON" />.
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
    ///         A list of the attestation certificate public key identifiers encoded as hex string. This value MUST be calculated according to method 1 for computing the keyIdentifier as defined in
    ///         <a href="https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.2">[RFC5280] section 4.2.1.2</a>.
    ///         <list type="bullet">
    ///             <item>
    ///                 <description>The hex string MUST NOT contain any non-hex characters (e.g. spaces).</description>
    ///             </item>
    ///             <item>
    ///                 <description>All hex letters MUST be lower case.</description>
    ///             </item>
    ///             <item>
    ///                 <description>This field MUST be set if neither aaid nor aaguid are set. Setting this field implies that the attestation certificate(s) are dedicated to a single authenticator model.</description>
    ///             </item>
    ///         </list>
    ///     </para>
    /// </param>
    /// <param name="metadataStatement">The metadataStatement JSON object as defined in <a href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#metadata-keys">[FIDOMetadataStatement]</a>.</param>
    /// <param name="biometricStatusReports">
    ///     Status of the FIDO Biometric Certification of one or more biometric components of the Authenticator <a href="https://fidoalliance.org/specs/biometric/requirements/Biometrics-Requirements-v2.0-fd-20201006.html">[FIDOBiometricsRequirements]</a>
    ///     .
    /// </param>
    /// <param name="statusReports">An array of status reports applicable to this authenticator.</param>
    /// <param name="timeOfLastStatusChange">ISO-8601 formatted date since when the status report array was set to the current value.</param>
    /// <param name="rogueListUrl">URL of a list of rogue (i.e. untrusted) individual authenticators.</param>
    /// <param name="rogueListHash">
    ///     <para>base64url(string[1..512])</para>
    ///     <para>
    ///         The hash value computed over the Base64url encoding of the UTF-8 representation of the JSON encoded rogueList available at rogueListURL (with type rogueListEntry[]). The hash algorithm related to the signature algorithm specified in the JWTHeader (see
    ///         <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob">Metadata BLOB</a>) MUST be used.
    ///     </para>
    ///     <para>This hash value MUST be present and non-empty whenever rogueListURL is present.</para>
    /// </param>
    [JsonConstructor]
    public MetadataBLOBPayloadEntryJSON(
        string? aaid,
        string? aaguid,
        string[]? attestationCertificateKeyIdentifiers,
        MetadataStatementJSON? metadataStatement,
        BiometricStatusReportJSON[]? biometricStatusReports,
        StatusReportJSON[] statusReports,
        string timeOfLastStatusChange,
        string? rogueListUrl,
        string? rogueListHash)
    {
        Aaid = aaid;
        Aaguid = aaguid;
        AttestationCertificateKeyIdentifiers = attestationCertificateKeyIdentifiers;
        MetadataStatement = metadataStatement;
        BiometricStatusReports = biometricStatusReports;
        StatusReports = statusReports;
        TimeOfLastStatusChange = timeOfLastStatusChange;
        RogueListURL = rogueListUrl;
        RogueListHash = rogueListHash;
    }

    /// <summary>
    ///     The AAID of the authenticator this metadata BLOB payload entry relates to. See <a href="https://fidoalliance.org/specs/fido-uaf-v1.2-ps-20201020/fido-uaf-protocol-v1.2-ps-20201020.html#authenticator-attestation-id-aaid-typedef">[UAFProtocol]</a> for the definition of the
    ///     AAID structure. This field MUST be set if the authenticator implements FIDO UAF.
    /// </summary>
    /// <remarks>
    ///     FIDO UAF authenticators support AAID, but they don't support AAGUID.
    /// </remarks>
    [JsonPropertyName("aaid")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string? Aaid { get; }

    /// <summary>
    ///     The Authenticator Attestation GUID. See <a href="https://fidoalliance.org/specs/fido-v2.0-ps-20150904/fido-key-attestation-v2.0-ps-20150904.html#attributes-2">[FIDOKeyAttestation]</a> for the definition of the AAGUID structure. This field MUST be set if the authenticator
    ///     implements FIDO2.
    /// </summary>
    /// <remarks>
    ///     FIDO2 authenticators support AAGUID, but they don't support AAID.
    /// </remarks>
    [JsonPropertyName("aaguid")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string? Aaguid { get; }

    /// <summary>
    ///     <para>
    ///         A list of the attestation certificate public key identifiers encoded as hex string. This value MUST be calculated according to method 1 for computing the keyIdentifier as defined in
    ///         <a href="https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.2">[RFC5280] section 4.2.1.2</a>.
    ///         <list type="bullet">
    ///             <item>
    ///                 <description>The hex string MUST NOT contain any non-hex characters (e.g. spaces).</description>
    ///             </item>
    ///             <item>
    ///                 <description>All hex letters MUST be lower case.</description>
    ///             </item>
    ///             <item>
    ///                 <description>This field MUST be set if neither aaid nor aaguid are set. Setting this field implies that the attestation certificate(s) are dedicated to a single authenticator model.</description>
    ///             </item>
    ///         </list>
    ///     </para>
    /// </summary>
    /// <remarks>
    ///     FIDO U2F authenticators do not support AAID nor AAGUID, but they use attestation certificates dedicated to a single authenticator model.
    /// </remarks>
    [JsonPropertyName("attestationCertificateKeyIdentifiers")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string[]? AttestationCertificateKeyIdentifiers { get; }

    /// <summary>
    ///     The metadataStatement JSON object as defined in <a href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#metadata-keys">[FIDOMetadataStatement]</a>.
    /// </summary>
    [JsonPropertyName("metadataStatement")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public MetadataStatementJSON? MetadataStatement { get; }

    /// <summary>
    ///     Status of the FIDO Biometric Certification of one or more biometric components of the Authenticator <a href="https://fidoalliance.org/specs/biometric/requirements/Biometrics-Requirements-v2.0-fd-20201006.html">[FIDOBiometricsRequirements]</a>.
    /// </summary>
    [JsonPropertyName("biometricStatusReports")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public BiometricStatusReportJSON[]? BiometricStatusReports { get; }

    /// <summary>
    ///     An array of status reports applicable to this authenticator.
    /// </summary>
    [JsonPropertyName("statusReports")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public StatusReportJSON[] StatusReports { get; }

    /// <summary>
    ///     ISO-8601 formatted date since when the status report array was set to the current value.
    /// </summary>
    [JsonPropertyName("timeOfLastStatusChange")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string TimeOfLastStatusChange { get; }

    /// <summary>
    ///     URL of a list of rogue (i.e. untrusted) individual authenticators.
    /// </summary>
    [JsonPropertyName("rogueListURL")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    // ReSharper disable once InconsistentNaming
    public string? RogueListURL { get; }

    /// <summary>
    ///     <para>base64url(string[1..512])</para>
    ///     <para>
    ///         The hash value computed over the Base64url encoding of the UTF-8 representation of the JSON encoded rogueList available at rogueListURL (with type rogueListEntry[]). The hash algorithm related to the signature algorithm specified in the JWTHeader (see
    ///         <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob">Metadata BLOB</a>) MUST be used.
    ///     </para>
    ///     <para>This hash value MUST be present and non-empty whenever rogueListURL is present.</para>
    /// </summary>
    [JsonPropertyName("rogueListHash")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string? RogueListHash { get; }
}
