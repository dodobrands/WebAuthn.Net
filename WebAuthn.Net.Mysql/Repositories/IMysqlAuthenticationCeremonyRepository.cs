using WebAuthn.Net.Mysql.Models;

namespace WebAuthn.Net.Mysql.Repositories;

public interface IMysqlAuthenticationCeremonyRepository
{
    Task SaveAuthenticationCeremony(AuthenticationCeremonyModel ceremony, CancellationToken cancellationToken);
    Task<AuthenticationCeremonyModel?> FindAuthenticationCeremony(string authenticationCeremonyId, CancellationToken cancellationToken);
}
