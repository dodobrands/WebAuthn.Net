namespace WebAuthn.Net.Storage.SqlServer.Configuration.Options;

public class SqlServerOptions
{
    public string ConnectionString { get; set; } = null!;

    public SqlServerCeremonyTransactionOptions AuthenticationCeremony { get; set; } = new();

    public SqlServerCeremonyTransactionOptions RegistrationCeremony { get; set; } = new();
}
