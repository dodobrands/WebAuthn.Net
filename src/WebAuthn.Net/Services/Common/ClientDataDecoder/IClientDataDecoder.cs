using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Common.ClientDataDecoder.Models;

namespace WebAuthn.Net.Services.Common.ClientDataDecoder;

public interface IClientDataDecoder
{
    Result<CollectedClientData> Decode(string jsonText);
}
