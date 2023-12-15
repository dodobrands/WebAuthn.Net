using System.Data;

namespace WebAuthn.Net.Storage.PostgreSql.Configuration.Options;

public class PostgreSqlOptions
{
    public string ConnectionString { get; set; } = null!;

    public IsolationLevel? WebAuthnContextIsolationLevel { get; set; }
}
