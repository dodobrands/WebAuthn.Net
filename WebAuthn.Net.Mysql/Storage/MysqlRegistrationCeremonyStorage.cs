using WebAuthn.Net.Mysql.Models;
using WebAuthn.Net.Storage.RegistrationCeremony;
using WebAuthn.Net.Storage.RegistrationCeremony.Models;

namespace WebAuthn.Net.Mysql.Storage;

public class MysqlRegistrationCeremonyStorage<TContext> : IRegistrationCeremonyStorage<TContext>
    where TContext : MySqlWebAuthnContext
{
    public async Task<string> SaveAsync(TContext context, RegistrationCeremonyParameters registrationCeremony, CancellationToken cancellationToken)
    {
        await Task.Yield();
        throw new NotImplementedException();
    }

    public async Task<RegistrationCeremonyParameters?> FindAsync(TContext context, string registrationCeremonyId, CancellationToken cancellationToken)
    {
        await Task.Yield();
        throw new NotImplementedException();
    }

    public async Task RemoveAsync(TContext context, string registrationCeremonyId, CancellationToken cancellationToken)
    {
        await Task.Yield();
        throw new NotImplementedException();
    }
}
