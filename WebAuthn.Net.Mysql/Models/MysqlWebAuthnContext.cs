using Microsoft.AspNetCore.Http;
using MySqlConnector;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Mysql.Repositories;

namespace WebAuthn.Net.Mysql.Models;

public class MySqlWebAuthnContext : IWebAuthnContext
{
    public MySqlWebAuthnContext(HttpContext httpContext, MySqlConnection connection, MySqlTransaction transaction)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentNullException.ThrowIfNull(transaction);
        HttpContext = httpContext;
        Connection = connection;
        Transaction = transaction;
        AuthenticationCeremony = new MysqlAuthenticationCeremonyRepository(this);
    }

    public MySqlConnection Connection { get; }
    public MySqlTransaction Transaction { get; }
    public IMysqlAuthenticationCeremonyRepository AuthenticationCeremony { get; }
    public HttpContext HttpContext { get; }

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
