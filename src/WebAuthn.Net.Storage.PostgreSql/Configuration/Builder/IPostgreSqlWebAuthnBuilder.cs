using WebAuthn.Net.Configuration.Builder;
using WebAuthn.Net.Storage.PostgreSql.Models;

namespace WebAuthn.Net.Storage.PostgreSql.Configuration.Builder;

/// <summary>
///     Builder for configuring the DI collection of services responsible for handling WebAuthn operations with a PostgreSQL-based storage.
/// </summary>
/// <typeparam name="TContext">The type of context in which the WebAuthn operation will be performed. Must be <see cref="DefaultPostgreSqlContext" /> or its descendant.</typeparam>
public interface IPostgreSqlWebAuthnBuilder<TContext> : IWebAuthnBuilder<TContext>
    where TContext : DefaultPostgreSqlContext
{
}
