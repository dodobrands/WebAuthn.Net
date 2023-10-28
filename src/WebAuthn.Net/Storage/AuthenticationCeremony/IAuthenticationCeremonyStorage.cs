using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Storage.AuthenticationCeremony.Models;

namespace WebAuthn.Net.Storage.AuthenticationCeremony;

public interface IAuthenticationCeremonyStorage<TContext>
    where TContext : class, IWebAuthnContext
{
    Task<string> SaveAsync(
        TContext context,
        AuthenticationCeremonyParameters authenticationCeremony,
        CancellationToken cancellationToken);

    Task<AuthenticationCeremonyParameters?> FindAsync(
        TContext context,
        string authenticationCeremonyId,
        CancellationToken cancellationToken);

    Task RemoveAsync(
        TContext context,
        string authenticationCeremonyId,
        CancellationToken cancellationToken);
}
