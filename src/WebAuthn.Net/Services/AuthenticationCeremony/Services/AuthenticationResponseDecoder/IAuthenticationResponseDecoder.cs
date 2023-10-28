using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Models.Protocol.AuthenticationCeremony.VerifyAssertion;
using WebAuthn.Net.Models.Protocol.Json.AuthenticationCeremony.VerifyAssertion;

namespace WebAuthn.Net.Services.AuthenticationCeremony.Services.AuthenticationResponseDecoder;

public interface IAuthenticationResponseDecoder<TContext>
    where TContext : class, IWebAuthnContext
{
    Task<Result<AuthenticationResponse>> DecodeAsync(
        TContext context,
        AuthenticationResponseJSON authenticationResponse,
        CancellationToken cancellationToken);
}
