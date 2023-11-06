using WebAuthn.Net.Storage.RegistrationCeremony.Models;

namespace WebAuthn.Net.Storage.RegistrationCeremony.Implementation.Models;

public class RegistrationCeremonyParametersCookieContainer
{
    public RegistrationCeremonyParametersCookieContainer(string id, RegistrationCeremonyParameters registrationCeremonyParameters)
    {
        Id = id;
        RegistrationCeremonyParameters = registrationCeremonyParameters;
    }

    public string Id { get; }

    public RegistrationCeremonyParameters RegistrationCeremonyParameters { get; }
}
