using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Models.Protocol.Json.RegistrationCeremony.CreateOptions;
using WebAuthn.Net.Models.Protocol.RegistrationCeremony.CreateOptions;

namespace WebAuthn.Net.Services.RegistrationCeremony.Services.PublicKeyCredentialCreationOptionsEncoder;

public interface IPublicKeyCredentialCreationOptionsEncoder<TContext>
    where TContext : class, IWebAuthnContext
{
    Task<PublicKeyCredentialCreationOptionsJSON> EncodeAsync(
        TContext context,
        PublicKeyCredentialCreationOptions options,
        CancellationToken cancellationToken);
}
