using Microsoft.AspNetCore.Http;
using Npgsql;
using WebAuthn.Net.Models.Abstractions;

namespace WebAuthn.Net.Storage.Postgres.Models;

public class DefaultPostgreSqlContext : IWebAuthnContext
{
    public DefaultPostgreSqlContext(HttpContext httpContext, NpgsqlConnection connection, NpgsqlTransaction transaction)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentNullException.ThrowIfNull(transaction);
        HttpContext = httpContext;
        Connection = connection;
        Transaction = transaction;
    }

    public NpgsqlConnection Connection { get; }
    public NpgsqlTransaction Transaction { get; }

    public HttpContext HttpContext { get; }

    public async Task CommitAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await Transaction.CommitAsync(cancellationToken);
    }

    public async ValueTask DisposeAsync()
    {
        GC.SuppressFinalize(this);
        await DisposeAsyncCore();
    }

    protected virtual async ValueTask DisposeAsyncCore()
    {
        await Connection.DisposeAsync();
        await Transaction.DisposeAsync();
    }
}
