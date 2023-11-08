using WebAuthn.Net.Configuration.Builder;
using WebAuthn.Net.Storage.Postgres.Models;

namespace WebAuthn.Net.Storage.Postgres.Configuration.Builder;

public interface IPostgreSqlWebAuthnBuilder<TContext> : IWebAuthnBuilder<TContext>
    where TContext : DefaultPostgreSqlContext
{
}
