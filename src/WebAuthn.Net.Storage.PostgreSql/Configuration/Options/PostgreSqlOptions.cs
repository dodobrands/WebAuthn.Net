using System.Data;

namespace WebAuthn.Net.Storage.PostgreSql.Configuration.Options;

/// <summary>
///     Options for PostgreSQL-based storage.
/// </summary>
public class PostgreSqlOptions
{
    /// <summary>
    ///     The database connection string that the storage will use.
    /// </summary>
    public string ConnectionString { get; set; } = null!;

    /// <summary>
    ///     Transaction isolation level for WebAuthn operations.
    /// </summary>
    public IsolationLevel? WebAuthnContextIsolationLevel { get; set; }
}
