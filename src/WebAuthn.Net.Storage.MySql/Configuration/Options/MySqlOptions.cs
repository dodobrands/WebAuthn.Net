using System.Data;

namespace WebAuthn.Net.Storage.MySql.Configuration.Options;

public class MySqlOptions
{
    public string ConnectionString { get; set; } = null!;

    public IsolationLevel? WebAuthnContextIsolationLevel { get; set; }
}
