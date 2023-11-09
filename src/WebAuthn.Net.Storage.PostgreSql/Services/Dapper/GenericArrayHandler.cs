using System;
using System.Data;
using Dapper;

namespace WebAuthn.Net.Storage.PostgreSql.Services.Dapper;

/// <summary>
///     https://www.niedermann.dk/2021/09/23/using-the-postgresql-array-type-with-dapper/
/// </summary>
public class GenericArrayHandler<T> : SqlMapper.TypeHandler<T[]>
{
    public override void SetValue(IDbDataParameter parameter, T[]? value)
    {
        ArgumentNullException.ThrowIfNull(parameter);
        parameter.Value = value;
    }

    public override T[] Parse(object value)
    {
        return (T[]) value;
    }
}
