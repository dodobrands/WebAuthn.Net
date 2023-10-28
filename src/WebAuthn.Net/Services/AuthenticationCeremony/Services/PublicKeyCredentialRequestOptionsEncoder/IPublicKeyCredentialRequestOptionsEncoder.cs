using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Models.Protocol.AuthenticationCeremony.CreateOptions;
using WebAuthn.Net.Models.Protocol.Json.AuthenticationCeremony.CreateOptions;

namespace WebAuthn.Net.Services.AuthenticationCeremony.Services.PublicKeyCredentialRequestOptionsEncoder;

public interface IPublicKeyCredentialRequestOptionsEncoder<TContext>
    where TContext : class, IWebAuthnContext
{
    Task<PublicKeyCredentialRequestOptionsJSON> EncodeAsync(
        TContext context,
        PublicKeyCredentialRequestOptions options,
        CancellationToken cancellationToken);
}
