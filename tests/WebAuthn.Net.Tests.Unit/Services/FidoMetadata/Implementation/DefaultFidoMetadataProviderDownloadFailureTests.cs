using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NUnit.Framework;
using WebAuthn.Net.Configuration.Options;
using WebAuthn.Net.DSL.Fakes;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataProvider;
using WebAuthn.Net.Services.Serialization.Json.Implementation;

namespace WebAuthn.Net.Services.FidoMetadata.Implementation;

public class DefaultFidoMetadataProviderDownloadFailureTests
{
    private static readonly DateTimeOffset CurrentDate = DateTimeOffset.Parse("2026-10-17T17:20:02.0000000+00:00", CultureInfo.InvariantCulture);

    private static readonly Exception[] DownloadExceptions =
    {
        new HttpRequestException("The response body exceeds the maximum allowed size"),
        new TimeoutException("The download wasn't completed within the download timeout"),
        new IOException("The connection was reset")
    };

    private OptionsMonitor<WebAuthnOptions> Options { get; set; } = null!;
    private ConfigurationManager ConfigurationManager { get; set; } = null!;
    private FakeLogger<DefaultFidoMetadataProvider> Logger { get; set; } = null!;

    [SetUp]
    public void SetupServices()
    {
        ConfigurationManager = new();
        var webAuthnOptions = FakeWebAuthnOptionsFactory.Create(ConfigurationManager);
        var optionsCache = new OptionsCache<WebAuthnOptions>();
        optionsCache.TryAdd(string.Empty, webAuthnOptions);
        Options = new(
            new OptionsFactory<WebAuthnOptions>(
                new List<IConfigureOptions<WebAuthnOptions>>(),
                new List<IPostConfigureOptions<WebAuthnOptions>>()),
            new List<IOptionsChangeTokenSource<WebAuthnOptions>>
            {
                new ConfigurationChangeTokenSource<WebAuthnOptions>(ConfigurationManager)
            },
            optionsCache);
        Logger = new();
    }

    [TearDown]
    public void TearDownServices()
    {
        Options.Dispose();
        ConfigurationManager.Dispose();
    }

    [TestCaseSource(nameof(DownloadExceptions))]
    public async Task DefaultFidoMetadataProvider_DownloadMetadata_WhenDownloadThrows_ReturnsFailAndWarns(Exception exception)
    {
        // A failed download must be a clean failure (Result.Fail + Warning): an exception would break the start of the application
        // (the first download is awaited in StartAsync) or silently terminate the background ingestion loop.
        var provider = CreateProvider(new ThrowingFidoMetadataHttpClient(exception));

        var result = await provider.DownloadMetadataAsync(CancellationToken.None);

        Assert.That(result.HasError, Is.True);
        var warnings = Logger.Entries.Where(static x => x.Level == LogLevel.Warning).ToArray();
        Assert.That(warnings, Has.Length.EqualTo(1));
        Assert.That(warnings[0].Message, Does.Contain("can't be downloaded"));
        Assert.That(warnings[0].Exception, Is.SameAs(exception));
    }

    [TestCase("<html><body>Service unavailable</body></html>")]
    [TestCase("a.b.c")]
    [TestCase("")]
    public async Task DefaultFidoMetadataProvider_DownloadMetadata_WhenDownloadedDataIsNotJwt_ReturnsFailAndWarns(string rawMetadata)
    {
        // A hostile or broken endpoint can return anything with a successful status code; the data must be rejected without an exception.
        var provider = CreateProvider(new StaticFidoMetadataHttpClient(rawMetadata));

        var result = await provider.DownloadMetadataAsync(CancellationToken.None);

        Assert.That(result.HasError, Is.True);
        var warnings = Logger.Entries.Where(static x => x.Level == LogLevel.Warning).ToArray();
        Assert.That(warnings, Has.Length.EqualTo(1));
        Assert.That(warnings[0].Message, Does.Contain("is not a JWS (JWT)"));
    }

    [Test]
    public async Task DefaultFidoMetadataProvider_DownloadMetadata_WhenDownloadIsCancelled_PropagatesCancellation()
    {
        // The cancellation requested by the caller (for example, the shutdown of the application) is not a download failure and must not be swallowed.
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();
        var provider = CreateProvider(new ThrowingFidoMetadataHttpClient(new OperationCanceledException(cts.Token)));

        await Assert.CatchAsync<OperationCanceledException>(async () => await provider.DownloadMetadataAsync(CancellationToken.None));

        Assert.That(Logger.Entries.Where(static x => x.Level >= LogLevel.Warning), Is.Empty);
    }

    private DefaultFidoMetadataProvider CreateProvider(IFidoMetadataHttpClient metadataHttpClient)
    {
        return new(
            Options,
            new DefaultSafeJsonSerializer(NullLogger<DefaultSafeJsonSerializer>.Instance),
            metadataHttpClient,
            new FakeTimeProvider(CurrentDate),
            Logger);
    }

    private sealed class ThrowingFidoMetadataHttpClient : IFidoMetadataHttpClient
    {
        private readonly Exception _exception;

        public ThrowingFidoMetadataHttpClient(Exception exception)
        {
            _exception = exception;
        }

        public Task<string> DownloadMetadataAsync(CancellationToken cancellationToken)
        {
            return Task.FromException<string>(_exception);
        }
    }

    private sealed class StaticFidoMetadataHttpClient : IFidoMetadataHttpClient
    {
        private readonly string _rawMetadata;

        public StaticFidoMetadataHttpClient(string rawMetadata)
        {
            _rawMetadata = rawMetadata;
        }

        public Task<string> DownloadMetadataAsync(CancellationToken cancellationToken)
        {
            return Task.FromResult(_rawMetadata);
        }
    }
}
