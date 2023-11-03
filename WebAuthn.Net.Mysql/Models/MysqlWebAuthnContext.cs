using Microsoft.AspNetCore.Http;
using MySqlConnector;
using WebAuthn.Net.Models.Abstractions;

namespace WebAuthn.Net.Mysql.Models;

public class MySqlWebAuthnContext : IWebAuthnContext
{
    public HttpContext HttpContext { get; }
    protected MySqlConnection Connection { get; }
    protected MySqlTransaction Transaction { get; }

    public MySqlWebAuthnContext(HttpContext httpContext, MySqlConnection connection, MySqlTransaction transaction)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentNullException.ThrowIfNull(transaction);
        HttpContext = httpContext;
        Connection = connection;
        Transaction = transaction;
    }

    public async Task CommitAsync(CancellationToken cancellationToken)
    {
        await Transaction.CommitAsync(cancellationToken);
    }

    public async ValueTask DisposeAsync()
    {
        GC.SuppressFinalize(this);
        await Transaction.DisposeAsync();
        await Connection.DisposeAsync();
    }
}
