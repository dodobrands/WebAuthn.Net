using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Protocol.Json.RegistrationCeremony.CreateCredential;
using WebAuthn.Net.Models.Protocol.RegistrationCeremony.CreateCredential;

namespace WebAuthn.Net.Services.RegistrationCeremony.Services.RegistrationResponseDecoder;

public interface IRegistrationResponseDecoder
{
    Result<RegistrationResponse> Decode(RegistrationResponseJSON registrationResponse);
}
