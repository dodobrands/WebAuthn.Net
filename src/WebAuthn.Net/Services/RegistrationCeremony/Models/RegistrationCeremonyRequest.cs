using System;
using WebAuthn.Net.Models.Protocol.RegistrationCeremony;

namespace WebAuthn.Net.Services.RegistrationCeremony.Models;

public class RegistrationCeremonyRequest
{
    public RegistrationCeremonyRequest(PublicKeyCredential credential)
    {
        ArgumentNullException.ThrowIfNull(credential);
        Credential = credential;
    }

    public PublicKeyCredential Credential { get; }
}
