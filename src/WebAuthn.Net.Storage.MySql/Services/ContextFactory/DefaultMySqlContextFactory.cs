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

/// <summary>
///     Default implementation of <see cref="IWebAuthnContextFactory{DefaultMySqlContext}" /> for MySQL-based storage.
/// </summary>
public class DefaultMySqlContextFactory : IWebAuthnContextFactory<DefaultMySqlContext>
{
    /// <summary>
    ///     Constructs <see cref="DefaultMySqlContextFactory" />.
    /// </summary>
    /// <param name="options">Accessor for getting the current value of options for MySQL-based storage.</param>
    /// <exception cref="ArgumentNullException">Any of the parameters is <see langword="null" /></exception>
    public DefaultMySqlContextFactory(IOptionsMonitor<MySqlOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);
        Options = options;
    }

    /// <summary>
    ///     Accessor for getting the current value of options for MySQL-based storage.
    /// </summary>
    protected IOptionsMonitor<MySqlOptions> Options { get; }

    /// <inheritdoc />
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

    /// <summary>
    ///     Asynchronously creates and opens a connection to MySQL.
    /// </summary>
    /// <param name="httpContext">The context of the HTTP request in which the WebAuthn operation is being processed.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>Open connection to MySQL database.</returns>
    protected virtual async Task<MySqlConnection> CreateConnectionAsync(
        HttpContext httpContext,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var connection = new MySqlConnection(Options.CurrentValue.ConnectionString);
        await connection.OpenAsync(cancellationToken);
        return connection;
    }

    /// <summary>
    ///     Asynchronously creates and opens a transaction in the specified connection to the MySQL database.
    /// </summary>
    /// <param name="httpContext">The context of the HTTP request in which the WebAuthn operation is being processed.</param>
    /// <param name="connection">Open connection to the MySQL database, for which a transaction will be opened.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>Open transaction to MySQL database.</returns>
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
