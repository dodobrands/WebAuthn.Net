using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Services.RegistrationCeremony.Models.CreateOptions.Protocol;
using WebAuthn.Net.Storage.Operations.Models;

namespace WebAuthn.Net.Storage.Operations;

public interface IOperationalStorage<TContext>
    where TContext : class, IWebAuthnContext
{
    Task<PublicKeyCredentialDescriptor[]?> GetExistingCredentialsAsync(
        TContext context,
        string rpId,
        byte[] userHandle,
        CancellationToken cancellationToken);

    Task<string> SaveRegistrationCeremonyOptionsAsync(
        TContext context,
        RegistrationCeremonyOptions registrationCeremonyOptions,
        CancellationToken cancellationToken);

    Task<RegistrationCeremonyOptions?> FindRegistrationCeremonyOptionsAsync(
        TContext context,
        string registrationCeremonyId,
        CancellationToken cancellationToken);
}
