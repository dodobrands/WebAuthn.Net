using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Models.Protocol;
using WebAuthn.Net.Models.Protocol.RegistrationCeremony;
using WebAuthn.Net.Storage.Operations.Models;

namespace WebAuthn.Net.Storage.Operations;

public interface IOperationalStorage<TContext>
    where TContext : class, IWebAuthnContext
{
    Task<PublicKeyCredentialDescriptor[]?> GetExistingCredentialsAsync(
        TContext context,
        PublicKeyCredentialRpEntity rp,
        PublicKeyCredentialUserEntity user,
        CancellationToken cancellationToken);

    Task<string> SaveRegistrationCeremonyOptionsAsync(
        TContext context,
        RegistrationCeremonyOptionsSaveRequest request,
        CancellationToken cancellationToken);

    Task<RegistrationCeremonyOptions?> FindRegistrationCeremonyOptionsAsync(
        TContext context,
        string registrationCeremonyId,
        CancellationToken cancellationToken);
}
