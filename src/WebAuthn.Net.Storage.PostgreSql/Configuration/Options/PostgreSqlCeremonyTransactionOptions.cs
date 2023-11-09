using System.Data;

namespace WebAuthn.Net.Storage.PostgreSql.Configuration.Options;

public class PostgreSqlCeremonyTransactionOptions
{
    public IsolationLevel? BeginCeremonyLevel { get; set; }
    public IsolationLevel? CompleteCeremonyLevel { get; set; }
}
