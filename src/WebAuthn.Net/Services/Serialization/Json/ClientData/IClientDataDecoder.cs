using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Serialization.Json.ClientData.Models;

namespace WebAuthn.Net.Services.Serialization.Json.ClientData;

public interface IClientDataDecoder
{
    Result<DecodedCollectedClientData> Decode(byte[] clientDataJson);
}
