using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataProvider.Protocol.Json;

/// <summary>
///     Metadata BLOB Payload dictionary
/// </summary>
/// <remarks>
///     <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#sctn-mds-payload-blob">FIDO Metadata Service - Metadata BLOB Payload dictionary</a>
/// </remarks>
// ReSharper disable once InconsistentNaming
public class MetadataBLOBPayloadJSON
{
    /// <summary>
    ///     Constructs <see cref="MetadataBLOBPayloadJSON" />.
    /// </summary>
    /// <param name="legalHeader">
    ///     The legalHeader, which MUST be in each BLOB, is an indication of the acceptance of the relevant legal agreement for using the MDS. The FIDO Alliance's Blob will contain this legal header: "legalHeader": "Retrieval and use of this BLOB indicates
    ///     acceptance of the appropriate agreement located at https://fidoalliance.org/metadata/metadata-legal-terms/"
    /// </param>
    /// <param name="no">The serial number of this UAF Metadata BLOB Payload. Serial numbers MUST be consecutive and strictly monotonic, i.e. the successor BLOB will have a no value exactly incremented by one.</param>
    /// <param name="nextUpdate">
    ///     <para>ISO-8601 formatted date when the next update will be provided at latest.</para>
    ///     <para>
    ///         The FIDO operational approach to publishing the FIDO Metadata has changed. The use of the "nextUpdate" field is discouraged and the field will be removed in the future. FIDO servers should ensure this field is not required by their code.
    ///     </para>
    /// </param>
    /// <param name="entries">List of zero or more MetadataBLOBPayloadEntry objects.</param>
    [JsonConstructor]
    public MetadataBLOBPayloadJSON(
        string? legalHeader,
        long no,
        string? nextUpdate,
        MetadataBLOBPayloadEntryJSON[] entries)
    {
        LegalHeader = legalHeader;
        No = no;
        NextUpdate = nextUpdate;
        Entries = entries;
    }

    /// <summary>
    ///     The legalHeader, which MUST be in each BLOB, is an indication of the acceptance of the relevant legal agreement for using the MDS. The FIDO Alliance's Blob will contain this legal header: "legalHeader": "Retrieval and use of this BLOB indicates acceptance of the appropriate
    ///     agreement located at https://fidoalliance.org/metadata/metadata-legal-terms/"
    /// </summary>
    [JsonPropertyName("legalHeader")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string? LegalHeader { get; }

    /// <summary>
    ///     The serial number of this UAF Metadata BLOB Payload. Serial numbers MUST be consecutive and strictly monotonic, i.e. the successor BLOB will have a no value exactly incremented by one.
    /// </summary>
    [JsonPropertyName("no")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public long No { get; }

    /// <summary>
    ///     ISO-8601 formatted date when the next update will be provided at latest.
    /// </summary>
    /// <remarks>
    ///     The FIDO operational approach to publishing the FIDO Metadata has changed. The use of the "nextUpdate" field is discouraged and the field will be removed in the future. FIDO servers should ensure this field is not required by their code.
    /// </remarks>
    [JsonPropertyName("nextUpdate")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string? NextUpdate { get; }

    /// <summary>
    ///     List of zero or more MetadataBLOBPayloadEntry objects.
    /// </summary>
    [JsonPropertyName("entries")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public MetadataBLOBPayloadEntryJSON[] Entries { get; }
}
