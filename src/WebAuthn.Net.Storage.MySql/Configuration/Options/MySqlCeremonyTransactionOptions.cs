using System.Data;

namespace WebAuthn.Net.Storage.MySql.Configuration.Options;

public class MySqlCeremonyTransactionOptions
{
    public IsolationLevel? BeginCeremonyLevel { get; set; }
    public IsolationLevel? CompleteCeremonyLevel { get; set; }
}
