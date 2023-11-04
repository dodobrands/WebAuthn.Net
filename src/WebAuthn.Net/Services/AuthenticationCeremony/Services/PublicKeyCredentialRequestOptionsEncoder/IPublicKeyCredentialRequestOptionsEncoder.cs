using WebAuthn.Net.Models.Protocol.AuthenticationCeremony.CreateOptions;
using WebAuthn.Net.Models.Protocol.Json.AuthenticationCeremony.CreateOptions;

namespace WebAuthn.Net.Services.AuthenticationCeremony.Services.PublicKeyCredentialRequestOptionsEncoder;

public interface IPublicKeyCredentialRequestOptionsEncoder
{
    PublicKeyCredentialRequestOptionsJSON Encode(PublicKeyCredentialRequestOptions options);
}
