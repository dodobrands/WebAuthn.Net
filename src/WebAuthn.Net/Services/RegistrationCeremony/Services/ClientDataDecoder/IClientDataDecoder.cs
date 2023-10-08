using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Services.RegistrationCeremony.Services.ClientDataDecoder.Models;

namespace WebAuthn.Net.Services.RegistrationCeremony.Services.ClientDataDecoder;

public interface IClientDataDecoder<TContext>
    where TContext : class, IWebAuthnContext
{
    Task<Result<CollectedClientData>> DecodeAsync(
        TContext context,
        string jsonText,
        CancellationToken cancellationToken);
}
