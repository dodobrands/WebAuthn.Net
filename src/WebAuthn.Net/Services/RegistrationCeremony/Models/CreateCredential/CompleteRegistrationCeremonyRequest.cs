using System;
using WebAuthn.Net.Models.Protocol.Json.RegistrationCeremony.CreateCredential;

namespace WebAuthn.Net.Services.RegistrationCeremony.Models.CreateCredential;

public class CompleteRegistrationCeremonyRequest
{
    public CompleteRegistrationCeremonyRequest(string registrationCeremonyId, RegistrationResponseJSON response)
    {
        ArgumentNullException.ThrowIfNull(registrationCeremonyId);
        ArgumentNullException.ThrowIfNull(response);
        RegistrationCeremonyId = registrationCeremonyId;
        Response = response;
    }

    public string RegistrationCeremonyId { get; }

    public RegistrationResponseJSON Response { get; }
}
