using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Storage.RegistrationCeremony.Models;

namespace WebAuthn.Net.Storage.RegistrationCeremony;

public interface IRegistrationCeremonyStorage<TContext>
    where TContext : class, IWebAuthnContext
{
    Task<string> SaveAsync(
        TContext context,
        RegistrationCeremonyParameters registrationCeremony,
        CancellationToken cancellationToken);

    Task<RegistrationCeremonyParameters?> FindAsync(
        TContext context,
        string registrationCeremonyId,
        CancellationToken cancellationToken);

    Task RemoveAsync(
        TContext context,
        string registrationCeremonyId,
        CancellationToken cancellationToken);
}
