using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Storage.AuthenticationCeremony;
using WebAuthn.Net.Storage.AuthenticationCeremony.Models;

namespace WebAuthn.Net.Mysql.Storage;

public sealed class MysqlAuthenticationCeremonyStorage
    : MysqlAuthenticationCeremonyStorage<IWebAuthnContext>
{
}

public class MysqlAuthenticationCeremonyStorage<TContext> : IAuthenticationCeremonyStorage<TContext>
    where TContext : class, IWebAuthnContext
{
    public async Task<string> SaveAsync(TContext context, AuthenticationCeremonyParameters authenticationCeremony, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public async Task<AuthenticationCeremonyParameters?> FindAsync(TContext context, string authenticationCeremonyId, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public async Task RemoveAsync(TContext context, string authenticationCeremonyId, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }
}
