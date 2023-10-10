using WebAuthn.Net.Models.Protocol.Json.RegistrationCeremony.CreateOptions;

namespace WebAuthn.Net.Services.RegistrationCeremony.Models.CreateOptions;

public class BeginRegistrationCeremonyResult
{
    public BeginRegistrationCeremonyResult(PublicKeyCredentialCreationOptionsJSON options, string registrationCeremonyId)
    {
        Options = options;
        RegistrationCeremonyId = registrationCeremonyId;
    }

    public PublicKeyCredentialCreationOptionsJSON Options { get; }

    public string RegistrationCeremonyId { get; }
}
