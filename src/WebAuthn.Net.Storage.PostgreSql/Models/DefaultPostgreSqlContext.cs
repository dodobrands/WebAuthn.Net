using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Npgsql;
using WebAuthn.Net.Models.Abstractions;

namespace WebAuthn.Net.Storage.PostgreSql.Models;

/// <summary>
///     Default implementation of <see cref="IWebAuthnContext" /> for PostgreSQL-based storage.
/// </summary>
public class DefaultPostgreSqlContext : IWebAuthnContext
{
    /// <summary>
    ///     Constructs <see cref="DefaultPostgreSqlContext" />.
    /// </summary>
    /// <param name="httpContext">The context of the HTTP request in which the WebAuthn operation is being processed.</param>
    /// <param name="connection">Open connection to PostgreSQL database.</param>
    /// <param name="transaction">Open transaction to PostgreSQL database.</param>
    /// <exception cref="ArgumentNullException">Any of the parameters is <see langword="null" /></exception>
    public DefaultPostgreSqlContext(HttpContext httpContext, NpgsqlConnection connection, NpgsqlTransaction transaction)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentNullException.ThrowIfNull(transaction);
        HttpContext = httpContext;
        Connection = connection;
        Transaction = transaction;
    }

    /// <summary>
    ///     Open connection to PostgreSQL database.
    /// </summary>
    public NpgsqlConnection Connection { get; }

    /// <summary>
    ///     Open transaction to PostgreSQL database.
    /// </summary>
    public NpgsqlTransaction Transaction { get; }

    /// <inheritdoc />
    public HttpContext HttpContext { get; }

    /// <inheritdoc />
    public virtual async Task CommitAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await Transaction.CommitAsync(cancellationToken);
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        await DisposeAsyncCore();
        GC.SuppressFinalize(this);
    }

    /// <summary>
    ///     Performs asynchronous release of unmanaged resources. May be overridden by descendants.
    /// </summary>
    protected virtual async ValueTask DisposeAsyncCore()
    {
        await Connection.DisposeAsync();
        await Transaction.DisposeAsync();
    }
}
