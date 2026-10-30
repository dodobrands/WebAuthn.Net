using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using MySqlConnector;
using NUnit.Framework;
using WebAuthn.Net.Storage.MySql.Configuration.Options;

namespace WebAuthn.Net.Storage.MySql.Services.ContextFactory;

public class DefaultMySqlContextFactoryTests
{
    [Test]
    public async Task CreateAsync_DisposesConnection_WhenRequestIsAbortedBeforeTransactionStarts()
    {
        using var requestAborted = new CancellationTokenSource();
        var factory = new UnopenedConnectionContextFactory(requestAborted);

        await Assert.ThrowsAsync<OperationCanceledException>(async () => await factory.CreateAsync(new DefaultHttpContext(), requestAborted.Token));

        Assert.That(factory.IsConnectionDisposed, Is.True);
    }

    [Test]
    public async Task CreateAsync_DisposesConnection_WhenTransactionCannotBeStarted()
    {
        var factory = new UnopenedConnectionContextFactory(null);

        await Assert.ThrowsAsync<InvalidOperationException>(async () => await factory.CreateAsync(new DefaultHttpContext(), CancellationToken.None));

        Assert.That(factory.IsConnectionDisposed, Is.True);
    }

    // Hands out a connection that is never opened, so the tests need no server and starting a transaction on it fails.
    private sealed class UnopenedConnectionContextFactory : DefaultMySqlContextFactory
    {
        private readonly CancellationTokenSource? _abortAfterConnecting;

        public UnopenedConnectionContextFactory(CancellationTokenSource? abortAfterConnecting)
            : base(new OptionsMonitorStub())
        {
            _abortAfterConnecting = abortAfterConnecting;
        }

        public bool IsConnectionDisposed { get; private set; }

        protected override async Task<MySqlConnection> CreateConnectionAsync(HttpContext httpContext, CancellationToken cancellationToken)
        {
            var connection = new MySqlConnection(Options.CurrentValue.ConnectionString);
            connection.Disposed += (_, _) => IsConnectionDisposed = true;
            if (_abortAfterConnecting is not null)
            {
                await _abortAfterConnecting.CancelAsync();
            }

            return connection;
        }
    }

    private sealed class OptionsMonitorStub : IOptionsMonitor<MySqlOptions>
    {
        public MySqlOptions CurrentValue { get; } = new()
        {
            ConnectionString = "Server=localhost;Database=webauthn"
        };

        public MySqlOptions Get(string? name)
        {
            return CurrentValue;
        }

        public IDisposable? OnChange(Action<MySqlOptions, string?> listener)
        {
            return null;
        }
    }
}
