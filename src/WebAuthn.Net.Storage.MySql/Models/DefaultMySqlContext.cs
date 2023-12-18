using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using MySqlConnector;
using WebAuthn.Net.Models.Abstractions;

namespace WebAuthn.Net.Storage.MySql.Models;

/// <summary>
///     Default implementation of <see cref="IWebAuthnContext" /> for MySQL-based storage.
/// </summary>
public class DefaultMySqlContext : IWebAuthnContext
{
    /// <summary>
    ///     Constructs <see cref="DefaultMySqlContext" />.
    /// </summary>
    /// <param name="httpContext">The context of the HTTP request in which the WebAuthn operation is being processed.</param>
    /// <param name="connection">Open connection to MySQL database.</param>
    /// <param name="transaction">Open transaction to MySQL database.</param>
    /// <exception cref="ArgumentNullException">Any of the parameters is <see langword="null" /></exception>
    public DefaultMySqlContext(HttpContext httpContext, MySqlConnection connection, MySqlTransaction transaction)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentNullException.ThrowIfNull(transaction);
        HttpContext = httpContext;
        Connection = connection;
        Transaction = transaction;
    }

    /// <summary>
    ///     Open connection to MySQL database.
    /// </summary>
    public MySqlConnection Connection { get; }

    /// <summary>
    ///     Open transaction to MySQL database.
    /// </summary>
    public MySqlTransaction Transaction { get; }

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
