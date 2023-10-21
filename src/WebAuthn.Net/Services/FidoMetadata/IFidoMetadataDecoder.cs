using WebAuthn.Net.Models;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataProvider.Protocol.Json;

namespace WebAuthn.Net.Services.FidoMetadata;

public interface IFidoMetadataDecoder
{
    Result<MetadataBlobPayload> Decode(MetadataBLOBPayloadJSON json);
}
