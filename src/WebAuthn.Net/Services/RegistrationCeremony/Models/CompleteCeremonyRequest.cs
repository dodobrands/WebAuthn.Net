using System;
using WebAuthn.Net.Models.Protocol.Json.RegistrationCeremony.CreateCredential.Input;

namespace WebAuthn.Net.Services.RegistrationCeremony.Models;

public class CompleteCeremonyRequest
{
    public CompleteCeremonyRequest(string registrationCeremonyId, RegistrationResponseJSON response)
    {
        ArgumentNullException.ThrowIfNull(registrationCeremonyId);
        ArgumentNullException.ThrowIfNull(response);
        RegistrationCeremonyId = registrationCeremonyId;
        Response = response;
    }

    public string RegistrationCeremonyId { get; }

    public RegistrationResponseJSON Response { get; }
}
