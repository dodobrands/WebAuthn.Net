using WebAuthn.Net.Configuration.Builder;
using WebAuthn.Net.Storage.SqlServer.Models;

namespace WebAuthn.Net.Storage.SqlServer.Configuration.Builder;

/// <summary>
///     Builder for configuring the DI collection of services responsible for handling WebAuthn operations with a Microsoft SQL Server-based storage.
/// </summary>
/// <typeparam name="TContext">The type of context in which the WebAuthn operation will be performed. Must be <see cref="DefaultSqlServerContext" /> or its descendant.</typeparam>
public interface ISqlServerWebAuthnBuilder<TContext> : IWebAuthnBuilder<TContext>
    where TContext : DefaultSqlServerContext
{
}
