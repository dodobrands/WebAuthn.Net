using WebAuthn.Net.Models.Protocol.Json.RegistrationCeremony.CreateOptions.Output;

namespace WebAuthn.Net.Services.RegistrationCeremony.Models.CreateOptions;

public class BeginCeremonyResult
{
    public BeginCeremonyResult(PublicKeyCredentialCreationOptionsJSON options, string registrationCeremonyId)
    {
        Options = options;
        RegistrationCeremonyId = registrationCeremonyId;
    }

    public PublicKeyCredentialCreationOptionsJSON Options { get; }

    public string RegistrationCeremonyId { get; }
}
