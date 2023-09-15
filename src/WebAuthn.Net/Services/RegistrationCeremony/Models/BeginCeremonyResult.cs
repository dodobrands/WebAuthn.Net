using WebAuthn.Net.Models.Protocol.RegistrationCeremony;

namespace WebAuthn.Net.Services.RegistrationCeremony.Models;

public class BeginCeremonyResult
{
    public BeginCeremonyResult(CredentialCreationOptions options, string registrationCeremonyId)
    {
        Options = options;
        RegistrationCeremonyId = registrationCeremonyId;
    }

    public CredentialCreationOptions Options { get; }

    public string RegistrationCeremonyId { get; }
}
