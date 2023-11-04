using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Protocol.AuthenticationCeremony.VerifyAssertion;
using WebAuthn.Net.Models.Protocol.Json.AuthenticationCeremony.VerifyAssertion;

namespace WebAuthn.Net.Services.AuthenticationCeremony.Services.AuthenticationResponseDecoder;

public interface IAuthenticationResponseDecoder
{
    Result<AuthenticationResponse> Decode(AuthenticationResponseJSON authenticationResponse);
}
