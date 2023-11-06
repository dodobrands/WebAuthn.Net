using WebAuthn.Net.Storage.AuthenticationCeremony.Models;

namespace WebAuthn.Net.Storage.AuthenticationCeremony.Implementation.Models;

public class AuthenticationCeremonyParametersCookieContainer
{
    public AuthenticationCeremonyParametersCookieContainer(string id, AuthenticationCeremonyParameters authenticationCeremonyParameters)
    {
        Id = id;
        AuthenticationCeremonyParameters = authenticationCeremonyParameters;
    }

    public string Id { get; }

    public AuthenticationCeremonyParameters AuthenticationCeremonyParameters { get; }
}
