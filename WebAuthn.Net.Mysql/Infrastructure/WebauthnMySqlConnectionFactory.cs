using MySqlConnector;

namespace WebAuthn.Net.Mysql.Infrastructure;

public interface IDbConnectionFactory
{
    Task<MySqlConnection> GetOpenConnectionAsync(CancellationToken cancellationToken = default);
    Task<MySqlConnection> GetOpenMigrationConnectionAsync(CancellationToken cancellationToken = default);
}

public class WebauthnMySqlConnectionFactory : IDbConnectionFactory
{
    private readonly string _connectionString;
    private readonly string _migratorConnectionString;

    public WebauthnMySqlConnectionFactory(string connectionString, string migratorConnectionString)
    {
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            throw new ArgumentException(@"Value cannot be null or whitespace.", nameof(connectionString));
        }

        if (string.IsNullOrWhiteSpace(migratorConnectionString))
        {
            throw new ArgumentException(@"Value cannot be null or whitespace.", nameof(migratorConnectionString));
        }

        _connectionString = connectionString;
        _migratorConnectionString = migratorConnectionString;
    }

    public async Task<MySqlConnection> GetOpenConnectionAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var connection = new MySqlConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);
        return connection;
    }

    public async Task<MySqlConnection> GetOpenMigrationConnectionAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var connection = new MySqlConnection(_migratorConnectionString);
        await connection.OpenAsync(cancellationToken);
        return connection;
    }
}
