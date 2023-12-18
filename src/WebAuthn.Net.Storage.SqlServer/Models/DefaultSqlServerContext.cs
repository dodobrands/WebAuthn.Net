using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Data.SqlClient;
using WebAuthn.Net.Models.Abstractions;

namespace WebAuthn.Net.Storage.SqlServer.Models;

/// <summary>
///     Default implementation of <see cref="IWebAuthnContext" /> for Microsoft SQL Server-based storage.
/// </summary>
public class DefaultSqlServerContext : IWebAuthnContext
{
    /// <summary>
    ///     Constructs <see cref="DefaultSqlServerContext" />.
    /// </summary>
    /// <param name="httpContext">The context of the HTTP request in which the WebAuthn operation is being processed.</param>
    /// <param name="connection">Open connection to Microsoft SQL Server database.</param>
    /// <param name="transaction">Open transaction to Microsoft SQL Server database.</param>
    /// <exception cref="ArgumentNullException">Any of the parameters is <see langword="null" /></exception>
    public DefaultSqlServerContext(HttpContext httpContext, SqlConnection connection, SqlTransaction transaction)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentNullException.ThrowIfNull(transaction);
        HttpContext = httpContext;
        Connection = connection;
        Transaction = transaction;
    }

    /// <summary>
    ///     Open connection to Microsoft SQL Server database.
    /// </summary>
    public SqlConnection Connection { get; }

    /// <summary>
    ///     Open transaction to Microsoft SQL Server database.
    /// </summary>
    public SqlTransaction Transaction { get; }

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
