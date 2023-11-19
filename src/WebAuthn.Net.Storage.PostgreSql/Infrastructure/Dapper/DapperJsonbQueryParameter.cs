using System;
using System.Data;
using Dapper;
using Npgsql;
using NpgsqlTypes;

namespace WebAuthn.Net.Storage.PostgreSql.Infrastructure.Dapper;

public class DapperJsonbQueryParameter : SqlMapper.ICustomQueryParameter
{
    private readonly string _value;

    public DapperJsonbQueryParameter(string value)
    {
        _value = value;
    }

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
