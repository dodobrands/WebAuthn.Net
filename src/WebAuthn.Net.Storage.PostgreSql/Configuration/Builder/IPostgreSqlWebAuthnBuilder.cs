using WebAuthn.Net.Configuration.Builder;
using WebAuthn.Net.Storage.PostgreSql.Models;

namespace WebAuthn.Net.Storage.PostgreSql.Configuration.Builder;

public interface IPostgreSqlWebAuthnBuilder<TContext> : IWebAuthnBuilder<TContext>
    where TContext : DefaultPostgreSqlContext
{
}
