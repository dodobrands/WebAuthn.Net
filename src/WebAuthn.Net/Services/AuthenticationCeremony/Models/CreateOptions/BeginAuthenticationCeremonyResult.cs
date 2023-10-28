using WebAuthn.Net.Models.Protocol.Json.AuthenticationCeremony.CreateOptions;

namespace WebAuthn.Net.Services.AuthenticationCeremony.Models.CreateOptions;

public class BeginAuthenticationCeremonyResult
{
    public BeginAuthenticationCeremonyResult(PublicKeyCredentialRequestOptionsJSON options, string authenticationCeremonyId)
    {
        Options = options;
        AuthenticationCeremonyId = authenticationCeremonyId;
    }

    public PublicKeyCredentialRequestOptionsJSON Options { get; }

    public string AuthenticationCeremonyId { get; }
}
