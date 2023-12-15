using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using MySqlConnector;
using WebAuthn.Net.Services.Context;
using WebAuthn.Net.Storage.MySql.Configuration.Options;
using WebAuthn.Net.Storage.MySql.Models;

namespace WebAuthn.Net.Storage.MySql.Services.ContextFactory;

public class DefaultMySqlContextFactory : IWebAuthnContextFactory<DefaultMySqlContext>
{
    public DefaultMySqlContextFactory(IOptionsMonitor<MySqlOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);
        Options = options;
    }

    protected IOptionsMonitor<MySqlOptions> Options { get; }

    public virtual async Task<DefaultMySqlContext> CreateAsync(
        HttpContext httpContext,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var connection = await CreateConnectionAsync(httpContext, cancellationToken);
        var transaction = await CreateTransactionAsync(httpContext, connection, cancellationToken);
        var context = new DefaultMySqlContext(httpContext, connection, transaction);
        return context;
    }

    protected virtual async Task<MySqlConnection> CreateConnectionAsync(
        HttpContext httpContext,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var connection = new MySqlConnection(Options.CurrentValue.ConnectionString);
        await connection.OpenAsync(cancellationToken);
        return connection;
    }

    protected virtual async Task<MySqlTransaction> CreateTransactionAsync(
        HttpContext httpContext,
        MySqlConnection connection,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(connection);
        cancellationToken.ThrowIfCancellationRequested();
        var options = Options.CurrentValue;
        if (options.WebAuthnContextIsolationLevel.HasValue)
        {
            return await connection.BeginTransactionAsync(
                options.WebAuthnContextIsolationLevel.Value,
                cancellationToken);
        }

        return await connection.BeginTransactionAsync(cancellationToken);
    }
}
