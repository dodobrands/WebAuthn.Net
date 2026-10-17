using WebAuthn.Net.Models;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataProvider.Protocol.Json;

namespace WebAuthn.Net.Services.FidoMetadata;

/// <summary>
///     Decoder for data received from the FIDO Metadata Service's blob
/// </summary>
public interface IFidoMetadataDecoder
{
    /// <summary>
    ///     Decodes data received from the FIDO Metadata Service's blob into a typed representation.
    /// </summary>
    /// <remarks>
    ///     <para>
    ///         According to the <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#sctn-mds-blob-proc-rules">Metadata BLOB object processing rules</a>, the entries of the blob are processed independently of each other.
    ///         An entry that cannot be decoded is skipped and doesn't affect the decoding of other entries, therefore the <see cref="MetadataBlobPayload.Entries" /> of the result contain only the successfully decoded entries.
    ///     </para>
    ///     <para>
    ///         The result indicates an error only if the blob itself is invalid or if the blob contains entries, but none of them could be decoded.
    ///     </para>
    /// </remarks>
    /// <param name="json">JSON model for deserializing the metadata blob.</param>
    /// <returns>If decoding was successful, the result contains the <see cref="MetadataBlobPayload" />, otherwise the result indicates that an error occurred</returns>
    Result<MetadataBlobPayload> Decode(MetadataBLOBPayloadJSON json);
}
