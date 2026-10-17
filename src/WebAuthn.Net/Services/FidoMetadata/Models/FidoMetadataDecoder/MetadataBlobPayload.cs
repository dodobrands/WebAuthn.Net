using System;

namespace WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder;

/// <summary>
///     Metadata BLOB Payload dictionary
/// </summary>
/// <remarks>
///     <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#sctn-mds-payload-blob">FIDO Metadata Service - Metadata BLOB Payload dictionary</a>
/// </remarks>
public class MetadataBlobPayload
{
    /// <summary>
    ///     Constructs <see cref="MetadataBlobPayload" />.
    /// </summary>
    /// <param name="legalHeader">
    ///     The legalHeader, which MUST be in each BLOB, is an indication of the acceptance of the relevant legal agreement for using the MDS. The FIDO Alliance's Blob will contain this legal header: "legalHeader": "Retrieval and use of this BLOB indicates
    ///     acceptance of the appropriate agreement located at https://fidoalliance.org/metadata/metadata-legal-terms/"
    /// </param>
    /// <param name="no">The serial number of this UAF Metadata BLOB Payload. Serial numbers MUST be consecutive and strictly monotonic, i.e. the successor BLOB will have a no value exactly incremented by one.</param>
    /// <param name="nextUpdate">Date when the next update will be provided at latest. The field is deprecated by the FIDO Metadata Service specification and may be absent.</param>
    /// <param name="entries">List of zero or more MetadataBLOBPayloadEntry objects.</param>
    /// <exception cref="ArgumentNullException"><paramref name="entries" /> is <see langword="null" /></exception>
    public MetadataBlobPayload(string? legalHeader, long no, DateTimeOffset? nextUpdate, MetadataBlobPayloadEntry[] entries)
    {
        ArgumentNullException.ThrowIfNull(entries);
        LegalHeader = legalHeader;
        No = no;
        NextUpdate = nextUpdate;
        Entries = entries;
    }

    /// <summary>
    ///     The legalHeader, which MUST be in each BLOB, is an indication of the acceptance of the relevant legal agreement for using the MDS. The FIDO Alliance's Blob will contain this legal header: "legalHeader": "Retrieval and use of this BLOB indicates acceptance of the appropriate
    ///     agreement located at https://fidoalliance.org/metadata/metadata-legal-terms/"
    /// </summary>
    public string? LegalHeader { get; }

    /// <summary>
    ///     The serial number of this UAF Metadata BLOB Payload. Serial numbers MUST be consecutive and strictly monotonic, i.e. the successor BLOB will have a no value exactly incremented by one.
    /// </summary>
    public long No { get; }

    /// <summary>
    ///     Date when the next update will be provided at latest.
    /// </summary>
    /// <remarks>
    ///     The FIDO operational approach to publishing the FIDO Metadata has changed. The use of the "nextUpdate" field is discouraged and the field will be removed in the future. FIDO servers should ensure this field is not required by their code.
    /// </remarks>
    public DateTimeOffset? NextUpdate { get; }

    /// <summary>
    ///     List of zero or more MetadataBLOBPayloadEntry objects.
    /// </summary>
    public MetadataBlobPayloadEntry[] Entries { get; }
}
