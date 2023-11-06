using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using MySqlConnector;
using WebAuthn.Net.Models.Enums;
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
        WebAuthnOperation operation,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var connection = await CreateConnectionAsync(httpContext, operation, cancellationToken);
        var transaction = await CreateTransactionAsync(httpContext, operation, connection, cancellationToken);
        var context = new DefaultMySqlContext(httpContext, connection, transaction);
        return context;
    }

    protected virtual async Task<MySqlConnection> CreateConnectionAsync(
        HttpContext httpContext,
        WebAuthnOperation operation,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var connection = new MySqlConnection(Options.CurrentValue.ConnectionString);
        await connection.OpenAsync(cancellationToken);
        return connection;
    }

    protected virtual async Task<MySqlTransaction> CreateTransactionAsync(
        HttpContext httpContext,
        WebAuthnOperation operation,
        MySqlConnection connection,
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
            return await connection.BeginTransactionAsync(isolationLevel.Value, cancellationToken);
        }

        return await connection.BeginTransactionAsync(cancellationToken);
    }
}
