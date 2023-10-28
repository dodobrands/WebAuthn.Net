using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Models.Protocol.Json.RegistrationCeremony.CreateCredential;
using WebAuthn.Net.Models.Protocol.RegistrationCeremony.CreateCredential;

namespace WebAuthn.Net.Services.RegistrationCeremony.Services.RegistrationResponseDecoder;

public interface IRegistrationResponseDecoder<TContext>
    where TContext : class, IWebAuthnContext
{
    Task<Result<RegistrationResponse>> DecodeAsync(
        TContext context,
        RegistrationResponseJSON registrationResponse,
        CancellationToken cancellationToken);
}
