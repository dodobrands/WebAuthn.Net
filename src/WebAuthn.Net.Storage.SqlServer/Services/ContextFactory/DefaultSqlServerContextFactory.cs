using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Options;
using WebAuthn.Net.Services.Context;
using WebAuthn.Net.Storage.SqlServer.Configuration.Options;
using WebAuthn.Net.Storage.SqlServer.Models;

namespace WebAuthn.Net.Storage.SqlServer.Services.ContextFactory;

/// <summary>
///     Default implementation of <see cref="IWebAuthnContextFactory{DefaultSqlServerContext}" /> for Microsoft SQL Server-based storage.
/// </summary>
public class DefaultSqlServerContextFactory : IWebAuthnContextFactory<DefaultSqlServerContext>
{
    /// <summary>
    ///     Constructs <see cref="DefaultSqlServerContextFactory" />.
    /// </summary>
    /// <param name="options">Accessor for getting the current value of options for Microsoft SQL Server-based storage.</param>
    /// <exception cref="ArgumentNullException">Any of the parameters is <see langword="null" /></exception>
    public DefaultSqlServerContextFactory(IOptionsMonitor<SqlServerOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);
        Options = options;
    }

    /// <summary>
    ///     Accessor for getting the current value of options for Microsoft SQL Server-based storage.
    /// </summary>
    protected IOptionsMonitor<SqlServerOptions> Options { get; }

    /// <inheritdoc />
    public virtual async Task<DefaultSqlServerContext> CreateAsync(
        HttpContext httpContext,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var connection = await CreateConnectionAsync(httpContext, cancellationToken);
        var transaction = await CreateTransactionAsync(httpContext, connection, cancellationToken);
        var context = new DefaultSqlServerContext(httpContext, connection, transaction);
        return context;
    }

    /// <summary>
    ///     Asynchronously creates and opens a connection to Microsoft SQL Server.
    /// </summary>
    /// <param name="httpContext">The context of the HTTP request in which the WebAuthn operation is being processed.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>Open connection to Microsoft SQL Server database.</returns>
    protected virtual async Task<SqlConnection> CreateConnectionAsync(
        HttpContext httpContext,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var connection = new SqlConnection(Options.CurrentValue.ConnectionString);
        await connection.OpenAsync(cancellationToken);
        return connection;
    }

    /// <summary>
    ///     Asynchronously creates and opens a transaction in the specified connection to the Microsoft SQL Server database.
    /// </summary>
    /// <param name="httpContext">The context of the HTTP request in which the WebAuthn operation is being processed.</param>
    /// <param name="connection">Open connection to the Microsoft SQL Server database, for which a transaction will be opened.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>Open transaction to Microsoft SQL Server database.</returns>
    protected virtual async Task<SqlTransaction> CreateTransactionAsync(
        HttpContext httpContext,
        SqlConnection connection,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(connection);
        cancellationToken.ThrowIfCancellationRequested();
        var options = Options.CurrentValue;
        if (options.WebAuthnContextIsolationLevel.HasValue)
        {
            return (SqlTransaction) await connection.BeginTransactionAsync(
                options.WebAuthnContextIsolationLevel.Value,
                cancellationToken);
        }

        return (SqlTransaction) await connection.BeginTransactionAsync(cancellationToken);
    }
}
