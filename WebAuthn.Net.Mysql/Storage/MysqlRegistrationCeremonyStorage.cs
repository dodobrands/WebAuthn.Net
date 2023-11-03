using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Storage.RegistrationCeremony;
using WebAuthn.Net.Storage.RegistrationCeremony.Models;

namespace WebAuthn.Net.Mysql.Storage;

public sealed class MysqlRegistrationCeremonyStorage : MysqlRegistrationCeremonyStorage<IWebAuthnContext>
{
}

public class MysqlRegistrationCeremonyStorage<TContext> : IRegistrationCeremonyStorage<TContext>
    where TContext : class, IWebAuthnContext
{
    public async Task<string> SaveAsync(TContext context, RegistrationCeremonyParameters registrationCeremony, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public async Task<RegistrationCeremonyParameters?> FindAsync(TContext context, string registrationCeremonyId, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public async Task RemoveAsync(TContext context, string registrationCeremonyId, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }
}
