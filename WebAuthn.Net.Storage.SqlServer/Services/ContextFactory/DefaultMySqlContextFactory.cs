using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Options;
using WebAuthn.Net.Models.Enums;
using WebAuthn.Net.Services.Context;
using WebAuthn.Net.Storage.SqlServer.Configuration.Options;
using WebAuthn.Net.Storage.SqlServer.Models;
using WebAuthn.Net.Storage.SqlServer.Configuration.Options;

namespace WebAuthn.Net.Storage.SqlServer.Services.ContextFactory;

public class DefaultSqlServerContextFactory : IWebAuthnContextFactory<DefaultSqlServerContext>
{
    public DefaultSqlServerContextFactory(IOptionsMonitor<SqlServerOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);
        Options = options;
    }

    protected IOptionsMonitor<SqlServerOptions> Options { get; }

    public virtual async Task<DefaultSqlServerContext> CreateAsync(
        HttpContext httpContext,
        WebAuthnOperation operation,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var connection = await CreateConnectionAsync(httpContext, operation, cancellationToken);
        var transaction = await CreateTransactionAsync(httpContext, operation, connection, cancellationToken);
        var context = new DefaultSqlServerContext(httpContext, connection, transaction);
        return context;
    }

    protected virtual async Task<SqlConnection> CreateConnectionAsync(
        HttpContext httpContext,
        WebAuthnOperation operation,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var connection = new SqlConnection(Options.CurrentValue.ConnectionString);
        await connection.OpenAsync(cancellationToken);
        return connection;
    }

    protected virtual async Task<SqlTransaction> CreateTransactionAsync(
        HttpContext httpContext,
        WebAuthnOperation operation,
        SqlConnection connection,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(connection);
        cancellationToken.ThrowIfCancellationRequested();
        var isolationLevel = operation switch
        {
            WebAuthnOperation.BeginAuthenticationCeremony => Options.CurrentValue.AuthenticationCeremony.BeginCeremonyLevel,
            WebAuthnOperation.CompleteAuthenticationCeremony => Options.CurrentValue.AuthenticationCeremony.CompleteCeremonyLevel,
            WebAuthnOperation.BeginRegistrationCeremony => Options.CurrentValue.RegistrationCeremony.BeginCeremonyLevel,
            WebAuthnOperation.CompleteRegistrationCeremony => Options.CurrentValue.RegistrationCeremony.CompleteCeremonyLevel,
            _ => throw new ArgumentOutOfRangeException(nameof(operation), operation, null)
        };
        if (isolationLevel.HasValue)
        {
            return (SqlTransaction) await connection.BeginTransactionAsync(isolationLevel.Value, cancellationToken);
        }

        return (SqlTransaction) await connection.BeginTransactionAsync(cancellationToken);
    }
}
