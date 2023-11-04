using WebAuthn.Net.Models.Protocol.Json.RegistrationCeremony.CreateOptions;
using WebAuthn.Net.Models.Protocol.RegistrationCeremony.CreateOptions;

namespace WebAuthn.Net.Services.RegistrationCeremony.Services.PublicKeyCredentialCreationOptionsEncoder;

public interface IPublicKeyCredentialCreationOptionsEncoder
{
    PublicKeyCredentialCreationOptionsJSON Encode(PublicKeyCredentialCreationOptions options);
}
