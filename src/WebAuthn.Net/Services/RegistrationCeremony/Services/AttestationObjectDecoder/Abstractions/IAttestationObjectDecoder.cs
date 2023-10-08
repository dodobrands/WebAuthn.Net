using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationObjectDecoder.Models;

namespace WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationObjectDecoder.Abstractions;

public interface IAttestationObjectDecoder<TContext>
    where TContext : class, IWebAuthnContext
{
    Task<Result<AttestationObject>> DecodeAsync(
        TContext context,
        byte[] attestationObject,
        CancellationToken cancellationToken);
}
