using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Npgsql;
using NUnit.Framework;
using WebAuthn.Net.Storage.PostgreSql.Configuration.Options;

namespace WebAuthn.Net.Storage.PostgreSql.Services.ContextFactory;

public class DefaultPostgreSqlContextFactoryTests
{
    [Test]
    public async Task CreateAsync_DisposesConnection_WhenRequestIsAbortedBeforeTransactionStarts()
    {
        using var requestAborted = new CancellationTokenSource();
        var factory = new UnopenedConnectionContextFactory(requestAborted);

        await Assert.ThrowsAsync<OperationCanceledException>(async () => await factory.CreateAsync(new DefaultHttpContext(), requestAborted.Token));

        AssertDisposed(factory.Connection);
    }

    [Test]
    public async Task CreateAsync_DisposesConnection_WhenTransactionCannotBeStarted()
    {
        var factory = new UnopenedConnectionContextFactory(null);

        await Assert.ThrowsAsync<InvalidOperationException>(async () => await factory.CreateAsync(new DefaultHttpContext(), CancellationToken.None));

        AssertDisposed(factory.Connection);
    }

    // Npgsql doesn't raise the Disposed event, but a disposed connection refuses to create commands.
    private static void AssertDisposed(NpgsqlConnection? connection)
    {
        Assert.That(connection, Is.Not.Null);
        Assert.Throws<ObjectDisposedException>(() => connection!.CreateCommand().Dispose());
    }

    // Hands out a connection that is never opened, so the tests need no server and starting a transaction on it fails.
    private sealed class UnopenedConnectionContextFactory : DefaultPostgreSqlContextFactory
    {
        private readonly CancellationTokenSource? _abortAfterConnecting;

        public UnopenedConnectionContextFactory(CancellationTokenSource? abortAfterConnecting)
            : base(new OptionsMonitorStub())
        {
            _abortAfterConnecting = abortAfterConnecting;
        }

        public NpgsqlConnection? Connection { get; private set; }

        protected override async Task<NpgsqlConnection> CreateConnectionAsync(HttpContext httpContext, CancellationToken cancellationToken)
        {
            var connection = new NpgsqlConnection(Options.CurrentValue.ConnectionString);
            Connection = connection;
            if (_abortAfterConnecting is not null)
            {
                await _abortAfterConnecting.CancelAsync();
            }

            return connection;
        }
    }

    private sealed class OptionsMonitorStub : IOptionsMonitor<PostgreSqlOptions>
    {
        public PostgreSqlOptions CurrentValue { get; } = new()
        {
            ConnectionString = "Host=localhost;Database=webauthn"
        };

        public PostgreSqlOptions Get(string? name)
        {
            return CurrentValue;
        }

        public IDisposable? OnChange(Action<PostgreSqlOptions, string?> listener)
        {
            return null;
        }
    }
}
