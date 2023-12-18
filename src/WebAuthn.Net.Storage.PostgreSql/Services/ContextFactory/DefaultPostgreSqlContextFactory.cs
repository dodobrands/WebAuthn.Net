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

/// <summary>
///     Default implementation of <see cref="IWebAuthnContextFactory{DefaultPostgreSqlContext}" /> for PostgreSQL-based storage.
/// </summary>
public class DefaultPostgreSqlContextFactory : IWebAuthnContextFactory<DefaultPostgreSqlContext>
{
    /// <summary>
    ///     Constructs <see cref="DefaultPostgreSqlContextFactory" />.
    /// </summary>
    /// <param name="options">Accessor for getting the current value of options for PostgreSQL-based storage.</param>
    /// <exception cref="ArgumentNullException">Any of the parameters is <see langword="null" /></exception>
    public DefaultPostgreSqlContextFactory(IOptionsMonitor<PostgreSqlOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);
        Options = options;
    }

    /// <summary>
    ///     Accessor for getting the current value of options for PostgreSQL-based storage.
    /// </summary>
    protected IOptionsMonitor<PostgreSqlOptions> Options { get; }

    /// <inheritdoc />
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

    /// <summary>
    ///     Asynchronously creates and opens a connection to PostgreSQL.
    /// </summary>
    /// <param name="httpContext">The context of the HTTP request in which the WebAuthn operation is being processed.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>Open connection to PostgreSQL database.</returns>
    protected virtual async Task<NpgsqlConnection> CreateConnectionAsync(
        HttpContext httpContext,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var connection = new NpgsqlConnection(Options.CurrentValue.ConnectionString);
        await connection.OpenAsync(cancellationToken);
        return connection;
    }

    /// <summary>
    ///     Asynchronously creates and opens a transaction in the specified connection to the PostgreSQL database.
    /// </summary>
    /// <param name="httpContext">The context of the HTTP request in which the WebAuthn operation is being processed.</param>
    /// <param name="connection">Open connection to the PostgreSQL database, for which a transaction will be opened.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>Open transaction to PostgreSQL database.</returns>
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
