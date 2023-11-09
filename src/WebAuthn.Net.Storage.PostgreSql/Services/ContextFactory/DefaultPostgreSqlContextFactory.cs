using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Npgsql;
using WebAuthn.Net.Models.Enums;
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
        WebAuthnOperation operation,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var connection = await CreateConnectionAsync(httpContext, operation, cancellationToken);
        var transaction = await CreateTransactionAsync(httpContext, operation, connection, cancellationToken);
        var context = new DefaultPostgreSqlContext(httpContext, connection, transaction);
        return context;
    }

    protected virtual async Task<NpgsqlConnection> CreateConnectionAsync(
        HttpContext httpContext,
        WebAuthnOperation operation,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var connection = new NpgsqlConnection(Options.CurrentValue.ConnectionString);
        await connection.OpenAsync(cancellationToken);
        return connection;
    }

    protected virtual async Task<NpgsqlTransaction> CreateTransactionAsync(
        HttpContext httpContext,
        WebAuthnOperation operation,
        NpgsqlConnection connection,
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
