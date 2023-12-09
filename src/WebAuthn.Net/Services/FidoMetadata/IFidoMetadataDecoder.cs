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
    /// <param name="json">JSON model for deserializing the metadata blob.</param>
    /// <returns>If decoding was successful, the result contains the <see cref="MetadataBlobPayload" />, otherwise the result indicates that an error occurred</returns>
    Result<MetadataBlobPayload> Decode(MetadataBLOBPayloadJSON json);
}
