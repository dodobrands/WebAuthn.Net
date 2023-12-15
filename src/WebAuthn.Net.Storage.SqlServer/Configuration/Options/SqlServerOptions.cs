using System.Data;

namespace WebAuthn.Net.Storage.SqlServer.Configuration.Options;

public class SqlServerOptions
{
    public string ConnectionString { get; set; } = null!;

    public IsolationLevel? WebAuthnContextIsolationLevel { get; set; }
}
