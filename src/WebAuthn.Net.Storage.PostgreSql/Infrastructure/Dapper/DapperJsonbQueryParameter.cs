using System;
using System.Data;
using Dapper;
using Npgsql;
using NpgsqlTypes;

namespace WebAuthn.Net.Storage.PostgreSql.Infrastructure.Dapper;

/// <summary>
///     Custom mapper for Dapper to work with jsonb values in PostgreSQL.
/// </summary>
public class DapperJsonbQueryParameter : SqlMapper.ICustomQueryParameter
{
    private readonly string _value;

    /// <summary>
    ///     Constructs <see cref="DapperJsonbQueryParameter" />.
    /// </summary>
    /// <param name="value">The value that will be written to the jsonb column.</param>
    public DapperJsonbQueryParameter(string value)
    {
        _value = value;
    }

    /// <inheritdoc />
    public void AddParameter(IDbCommand command, string name)
    {
        ArgumentNullException.ThrowIfNull(command);
        var parameter = new NpgsqlParameter(name, NpgsqlDbType.Jsonb)
        {
            Value = _value
        };
        command.Parameters.Add(parameter);
    }
}
