using WebAuthn.Net.Configuration.Builder;
using WebAuthn.Net.Storage.SqlServer.Models;

namespace WebAuthn.Net.Storage.SqlServer.Configuration.Builder;

public interface ISqlServerWebAuthnBuilder<TContext> : IWebAuthnBuilder<TContext>
    where TContext : DefaultSqlServerContext
{
}
