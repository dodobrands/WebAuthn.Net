using System;
using WebAuthn.Net.Models.Protocol.RegistrationCeremony;

namespace WebAuthn.Net.Services.RegistrationCeremony.Models;

public class CompleteCeremonyRequest
{
    public CompleteCeremonyRequest(string registrationCeremonyId, PublicKeyCredential credential)
    {
        ArgumentNullException.ThrowIfNull(registrationCeremonyId);
        ArgumentNullException.ThrowIfNull(credential);
        RegistrationCeremonyId = registrationCeremonyId;
        Credential = credential;
    }

    public string RegistrationCeremonyId { get; }

    public PublicKeyCredential Credential { get; }
}
