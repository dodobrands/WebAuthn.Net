using WebAuthn.Net.Configuration.Builder;
using WebAuthn.Net.Storage.MySql.Models;

namespace WebAuthn.Net.Storage.MySql.Configuration.Builder;

/// <summary>
///     Builder for configuring the DI collection of services responsible for handling WebAuthn operations with a MySQL-based storage.
/// </summary>
/// <typeparam name="TContext">The type of context in which the WebAuthn operation will be performed. Must be <see cref="DefaultMySqlContext" /> or its descendant.</typeparam>
public interface IMySqlWebAuthnBuilder<TContext> : IWebAuthnBuilder<TContext>
    where TContext : DefaultMySqlContext
{
}
