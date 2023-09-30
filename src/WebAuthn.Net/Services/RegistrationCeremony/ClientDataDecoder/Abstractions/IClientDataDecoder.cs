using WebAuthn.Net.Models;
using WebAuthn.Net.Services.RegistrationCeremony.Models.ClientDataDecoder;

namespace WebAuthn.Net.Services.RegistrationCeremony;

public interface IClientDataDecoder
{
    Result<CollectedClientData> Decode(byte[] clientDataJson);
}
