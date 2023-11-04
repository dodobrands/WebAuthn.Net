using System.Data;
using System.Text.Json;
using MySqlConnector;
using WebAuthn.Net.Mysql.Models;

namespace WebAuthn.Net.Mysql.Repositories;

public static class AuthenticationCeremonySql
{
    public const string Save = @"
INSERT INTO ""AuthenticationCeremony""
    (""Id"", ""UserHandle"", ""Options"", ""ExpectedRp"", ""CreatedAt"", ""ExpiresAt"")
VALUES
    (@id, @userHandle, @options, @expectedRp, @createdAt, @expiresAt);
    ";


    public const string Find = @"
SELECT ""Id"", ""UserHandle"", ""Options"", ""ExpectedRp"", ""CreatedAt"", ""ExpiresAt"" FROM ""AuthenticationCeremony""
WHERE ""Id"" = @id
";
}

public class MysqlAuthenticationCeremonyRepository : IMysqlAuthenticationCeremonyRepository
{
    private readonly MySqlWebAuthnContext _context;


    public MysqlAuthenticationCeremonyRepository(MySqlWebAuthnContext context)
    {
        _context = context;
    }

    public async Task SaveAuthenticationCeremony(AuthenticationCeremonyModel ceremony, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(ceremony);

        using var cmd = new MySqlCommand(AuthenticationCeremonySql.Save, _context.Connection, _context.Transaction);

        cmd.CommandType = CommandType.Text;
        cmd.Parameters.AddWithValue("@id", ceremony.Id);
        cmd.Parameters.AddWithValue("@userHandle", ceremony.UserHandle);
        cmd.Parameters.AddWithValue("@options", JsonSerializer.Serialize(ceremony.Options));
        cmd.Parameters.AddWithValue("@expectedRp", JsonSerializer.Serialize(ceremony.ExpectedRp));
        cmd.Parameters.AddWithValue("@createdAt", ceremony.CreatedAt);
        cmd.Parameters.AddWithValue("@expiresAt", ceremony.ExpiresAt);

        await cmd.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<AuthenticationCeremonyModel?> FindAuthenticationCeremony(string authenticationCeremonyId, CancellationToken cancellationToken)
    {
        if (!Guid.TryParse(authenticationCeremonyId, out var id))
        {
            throw new ArgumentNullException(nameof(authenticationCeremonyId));
        }

        using var cmd = new MySqlCommand(AuthenticationCeremonySql.Find, _context.Connection, _context.Transaction);

        cmd.CommandType = CommandType.Text;
        cmd.Parameters.AddWithValue("@id", id);

        using var reader = await cmd.ExecuteReaderAsync(cancellationToken);
        var schema = await reader.GetSchemaTableAsync(cancellationToken);
        if (schema is null || schema.Rows.Count is 0)
        {
            return null;
        }

        return null;
    }
}
