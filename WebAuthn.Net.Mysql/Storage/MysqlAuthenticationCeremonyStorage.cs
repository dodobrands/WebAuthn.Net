using WebAuthn.Net.Mysql.Models;
using WebAuthn.Net.Storage.AuthenticationCeremony;
using WebAuthn.Net.Storage.AuthenticationCeremony.Models;

namespace WebAuthn.Net.Mysql.Storage;

public class MysqlAuthenticationCeremonyStorage<TContext> : IAuthenticationCeremonyStorage<TContext>
    where TContext : MySqlWebAuthnContext
{
    public async Task<string> SaveAsync(TContext context, AuthenticationCeremonyParameters authenticationCeremony, CancellationToken cancellationToken)
    {
        await Task.Yield();
        var ceremony = AuthenticationCeremonyModel
            .FromAuthenticationCeremonyParameters(authenticationCeremony, Guid.NewGuid().ToString());

        return ceremony.Id;
    }

    public async Task<AuthenticationCeremonyParameters?> FindAsync(TContext context, string authenticationCeremonyId, CancellationToken cancellationToken)
    {
        await Task.Yield();
        throw new NotImplementedException();
    }

    public async Task RemoveAsync(TContext context, string authenticationCeremonyId, CancellationToken cancellationToken)
    {
        await Task.Yield();
        throw new NotImplementedException();
    }
}
