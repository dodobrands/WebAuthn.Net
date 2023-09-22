using WebAuthn.Net.Models;
using WebAuthn.Net.Services.RegistrationCeremony.Models.ClientData;

namespace WebAuthn.Net.Services.RegistrationCeremony;

public interface IClientDataDecoder
{
    Result<DecodedCollectedClientData> Decode(byte[] clientDataJson);
}
