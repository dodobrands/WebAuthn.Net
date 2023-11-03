using WebAuthn.Net.Mysql.Models;
using WebAuthn.Net.Storage.AuthenticationCeremony;
using WebAuthn.Net.Storage.AuthenticationCeremony.Models;

namespace WebAuthn.Net.Mysql.Storage;

public class MysqlAuthenticationCeremonyStorage<TContext> : IAuthenticationCeremonyStorage<TContext>
    where TContext : MySqlWebAuthnContext
{
    public async Task<string> SaveAsync(TContext context, AuthenticationCeremonyParameters authenticationCeremony, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        var ceremony = AuthenticationCeremonyModel.FromAuthenticationCeremonyParameters(authenticationCeremony, Guid.NewGuid().ToString());
        await context.AuthenticationCeremony.SaveAuthenticationCeremony(ceremony, cancellationToken);
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
