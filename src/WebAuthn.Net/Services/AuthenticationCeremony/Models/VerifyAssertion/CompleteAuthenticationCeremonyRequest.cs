using System;
using WebAuthn.Net.Models.Protocol.Json.AuthenticationCeremony.VerifyAssertion;

namespace WebAuthn.Net.Services.AuthenticationCeremony.Models.VerifyAssertion;

public class CompleteAuthenticationCeremonyRequest
{
    public CompleteAuthenticationCeremonyRequest(string authenticationCeremonyId, AuthenticationResponseJSON response)
    {
        ArgumentNullException.ThrowIfNull(authenticationCeremonyId);
        ArgumentNullException.ThrowIfNull(response);
        AuthenticationCeremonyId = authenticationCeremonyId;
        Response = response;
    }

    public string AuthenticationCeremonyId { get; }

    public AuthenticationResponseJSON Response { get; }
}
