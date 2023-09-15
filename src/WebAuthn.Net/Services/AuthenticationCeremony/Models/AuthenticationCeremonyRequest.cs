using System;
using WebAuthn.Net.Models.Protocol.AuthenticationCeremony;

namespace WebAuthn.Net.Services.AuthenticationCeremony.Models;

public class AuthenticationCeremonyRequest
{
    public AuthenticationCeremonyRequest(PublicKeyCredential credential)
    {
        ArgumentNullException.ThrowIfNull(credential);
        Credential = credential;
    }

    public PublicKeyCredential Credential { get; }
}
