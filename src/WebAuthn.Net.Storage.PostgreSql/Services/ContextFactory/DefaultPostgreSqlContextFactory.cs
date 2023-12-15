using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Npgsql;
using WebAuthn.Net.Services.Context;
using WebAuthn.Net.Storage.PostgreSql.Configuration.Options;
using WebAuthn.Net.Storage.PostgreSql.Models;

namespace WebAuthn.Net.Storage.PostgreSql.Services.ContextFactory;

public class DefaultPostgreSqlContextFactory : IWebAuthnContextFactory<DefaultPostgreSqlContext>
{
    public DefaultPostgreSqlContextFactory(IOptionsMonitor<PostgreSqlOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);
        Options = options;
    }

    protected IOptionsMonitor<PostgreSqlOptions> Options { get; }

    public virtual async Task<DefaultPostgreSqlContext> CreateAsync(
        HttpContext httpContext,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var connection = await CreateConnectionAsync(httpContext, cancellationToken);
        var transaction = await CreateTransactionAsync(httpContext, connection, cancellationToken);
        var context = new DefaultPostgreSqlContext(httpContext, connection, transaction);
        return context;
    }

    protected virtual async Task<NpgsqlConnection> CreateConnectionAsync(
        HttpContext httpContext,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var connection = new NpgsqlConnection(Options.CurrentValue.ConnectionString);
        await connection.OpenAsync(cancellationToken);
        return connection;
    }

    protected virtual async Task<NpgsqlTransaction> CreateTransactionAsync(
        HttpContext httpContext,
        NpgsqlConnection connection,
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
