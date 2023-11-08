using System.Data;

namespace WebAuthn.Net.Storage.SqlServer.Configuration.Options;

public class SqlServerCeremonyTransactionOptions
{
    public IsolationLevel? BeginCeremonyLevel { get; set; }
    public IsolationLevel? CompleteCeremonyLevel { get; set; }
}
