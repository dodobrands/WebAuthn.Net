using WebAuthn.Net.Models;
using WebAuthn.Net.Services.RegistrationCeremony.ClientDataDecoder.Models;

namespace WebAuthn.Net.Services.RegistrationCeremony.ClientDataDecoder.Abstractions;

public interface IClientDataDecoder
{
    Result<CollectedClientData> Decode(byte[] clientDataJson);
}
