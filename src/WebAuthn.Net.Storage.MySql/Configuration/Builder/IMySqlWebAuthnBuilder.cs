using WebAuthn.Net.Configuration.Builder;
using WebAuthn.Net.Storage.MySql.Models;

namespace WebAuthn.Net.Storage.MySql.Configuration.Builder;

public interface IMySqlWebAuthnBuilder<TContext> : IWebAuthnBuilder<TContext>
    where TContext : DefaultMySqlContext
{
}
