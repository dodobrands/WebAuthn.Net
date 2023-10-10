using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Models.Protocol.Json.RegistrationCeremony.CreateOptions;
using WebAuthn.Net.Services.RegistrationCeremony.Models.CreateOptions.Protocol;

namespace WebAuthn.Net.Services.RegistrationCeremony.Services.OptionsEncoder;

public interface IOptionsEncoder<TContext>
    where TContext : class, IWebAuthnContext
{
    Task<PublicKeyCredentialCreationOptionsJSON> EncodeAsync(
        TContext context,
        PublicKeyCredentialCreationOptions options,
        CancellationToken cancellationToken);
}
