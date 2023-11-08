﻿namespace WebAuthn.Net.Storage.Postgres.Configuration.Options;

public class PostgreSqlOptions
{
    public string ConnectionString { get; set; } = null!;

    public PostgreSqlCeremonyTransactionOptions AuthenticationCeremony { get; set; } = new();

    public PostgreSqlCeremonyTransactionOptions RegistrationCeremony { get; set; } = new();
}
