﻿using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using MySqlConnector;
using WebAuthn.Net.Models.Abstractions;

namespace WebAuthn.Net.Storage.MySql.Models;

public class DefaultMySqlContext : IWebAuthnContext
{
    public DefaultMySqlContext(HttpContext httpContext, MySqlConnection connection, MySqlTransaction transaction)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentNullException.ThrowIfNull(transaction);
        HttpContext = httpContext;
        Connection = connection;
        Transaction = transaction;
    }

    public MySqlConnection Connection { get; }
    public MySqlTransaction Transaction { get; }
    public HttpContext HttpContext { get; }

    public virtual async Task CommitAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await Transaction.CommitAsync(cancellationToken);
    }

    public async ValueTask DisposeAsync()
    {
        GC.SuppressFinalize(this);
        await DisposeAsyncCore();
    }

    protected virtual async ValueTask DisposeAsyncCore()
    {
        await Connection.DisposeAsync();
        await Transaction.DisposeAsync();
    }
}
