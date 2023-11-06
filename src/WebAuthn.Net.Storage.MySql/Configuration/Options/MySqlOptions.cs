namespace WebAuthn.Net.Storage.MySql.Configuration.Options;

public class MySqlOptions
{
    public string ConnectionString { get; set; } = null!;

    public MySqlCeremonyTransactionOptions AuthenticationCeremony { get; set; } = new();

    public MySqlCeremonyTransactionOptions RegistrationCeremony { get; set; } = new();
}
