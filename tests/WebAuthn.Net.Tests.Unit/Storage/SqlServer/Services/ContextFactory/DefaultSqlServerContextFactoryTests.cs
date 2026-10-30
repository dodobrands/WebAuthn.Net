using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Options;
using NUnit.Framework;
using WebAuthn.Net.Storage.SqlServer.Configuration.Options;

namespace WebAuthn.Net.Storage.SqlServer.Services.ContextFactory;

public class DefaultSqlServerContextFactoryTests
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
    private sealed class UnopenedConnectionContextFactory : DefaultSqlServerContextFactory
    {
        private readonly CancellationTokenSource? _abortAfterConnecting;

        public UnopenedConnectionContextFactory(CancellationTokenSource? abortAfterConnecting)
            : base(new OptionsMonitorStub())
        {
            _abortAfterConnecting = abortAfterConnecting;
        }

        public bool IsConnectionDisposed { get; private set; }

        protected override async Task<SqlConnection> CreateConnectionAsync(HttpContext httpContext, CancellationToken cancellationToken)
        {
            var connection = new SqlConnection(Options.CurrentValue.ConnectionString);
            connection.Disposed += (_, _) => IsConnectionDisposed = true;
            if (_abortAfterConnecting is not null)
            {
                await _abortAfterConnecting.CancelAsync();
            }

            return connection;
        }
    }

    private sealed class OptionsMonitorStub : IOptionsMonitor<SqlServerOptions>
    {
        public SqlServerOptions CurrentValue { get; } = new()
        {
            ConnectionString = "Server=localhost;Database=webauthn"
        };

        public SqlServerOptions Get(string? name)
        {
            return CurrentValue;
        }

        public IDisposable? OnChange(Action<SqlServerOptions, string?> listener)
        {
            return null;
        }
    }
}
