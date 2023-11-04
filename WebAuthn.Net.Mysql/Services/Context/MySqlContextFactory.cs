using Microsoft.AspNetCore.Http;
using WebAuthn.Net.Mysql.Infrastructure;
using WebAuthn.Net.Mysql.Models;
using WebAuthn.Net.Services.Context;

namespace WebAuthn.Net.Mysql.Services.Context;

public class DefaultMySqlContextFactory : IWebAuthnContextFactory<MySqlWebAuthnContext>
{
    public DefaultMySqlContextFactory(IDbConnectionFactory connectionFactory)
    {
        ArgumentNullException.ThrowIfNull(connectionFactory);
        ConnectionFactory = connectionFactory;
    }

    protected IDbConnectionFactory ConnectionFactory { get; }

    public virtual async Task<MySqlWebAuthnContext> CreateAsync(HttpContext httpContext, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var connection = await ConnectionFactory.GetOpenConnectionAsync(cancellationToken);
        var trx = await connection.BeginTransactionAsync(cancellationToken);
        return new(httpContext, connection, trx);
    }
}
