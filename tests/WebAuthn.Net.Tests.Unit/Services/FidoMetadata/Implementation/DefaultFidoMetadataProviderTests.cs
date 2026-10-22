using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
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
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataProvider.Constants;
using WebAuthn.Net.Services.Metrics;
using WebAuthn.Net.Services.Providers;
using WebAuthn.Net.Services.Serialization.Json;
using WebAuthn.Net.Services.Serialization.Json.Implementation;

namespace WebAuthn.Net.Services.FidoMetadata.Implementation;

public class DefaultFidoMetadataProviderTests
{
    private OptionsMonitor<WebAuthnOptions> Options { get; set; } = null!;
    private ConfigurationManager ConfigurationManager { get; set; } = null!;
    private FakeFidoMetadataHttpClientProvider FakeFidoHttpClientProvider { get; set; } = null!;
    private FakeFidoMetadataCounters Counters { get; set; } = null!;
    private DefaultFidoMetadataProvider MetadataProvider { get; set; } = null!;

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
        FakeFidoHttpClientProvider = new();
        var safeJsonDeserializer = new DefaultSafeJsonSerializer(NullLogger<DefaultSafeJsonSerializer>.Instance);
        Counters = new();
        MetadataProvider = new(
            Options,
            safeJsonDeserializer,
            FakeFidoHttpClientProvider.Client,
            CreateTimeProvider(),
            Counters,
            NullLogger<DefaultFidoMetadataProvider>.Instance);
    }

    private static FakeTimeProvider CreateTimeProvider()
    {
        return new(DateTimeOffset.Parse("2026-10-17T17:20:02.0000000+00:00", CultureInfo.InvariantCulture));
    }

    [TearDown]
    public virtual void TearDownServices()
    {
        FakeFidoHttpClientProvider.Dispose();
    }

    [Test]
    public async Task DefaultFidoMetadataProvider_DownloadMetadata_WhenCorrectDataDownloaded()
    {
        var result = await MetadataProvider.DownloadMetadataAsync(CancellationToken.None);
        Assert.That(result.HasError, Is.False);
        Assert.That(result.Ok, Is.Not.Null);
        Assert.Multiple(() =>
        {
            Assert.That(Counters.DownloadStarts, Is.EqualTo(1));
            Assert.That(Counters.SuccessfulDownloadEnds, Is.EqualTo(1));
            Assert.That(Counters.FailedDownloadEnds, Is.Zero);
            Assert.That(Counters.DownloadFailures, Is.Empty);
        });
    }

    [Test]
    public async Task DefaultFidoMetadataProvider_DownloadMetadata_WhenJwtCertificateChainIsAcceptedByAdditionalValidation()
    {
        var logger = new FakeLogger<DefaultFidoMetadataProvider>();
        var provider = CreateChainValidatingProvider(logger, true);

        var result = await provider.DownloadMetadataAsync(CancellationToken.None);

        Assert.That(result.HasError, Is.False);
        Assert.That(provider.ValidatedChainElements, Is.GreaterThanOrEqualTo(2));
        Assert.That(provider.ValidatedLeafThumbprint, Is.Not.Empty);
        Assert.That(logger.Entries.Where(static x => x.Level >= LogLevel.Warning), Is.Empty);
    }

    [Test]
    public async Task DefaultFidoMetadataProvider_DownloadMetadata_WhenJwtCertificateChainIsRejectedByAdditionalValidation()
    {
        var logger = new FakeLogger<DefaultFidoMetadataProvider>();
        var provider = CreateChainValidatingProvider(logger, false);

        var result = await provider.DownloadMetadataAsync(CancellationToken.None);

        Assert.That(result.HasError, Is.True);
        Assert.That(provider.ValidatedChainElements, Is.GreaterThanOrEqualTo(2));
        var warnings = logger.Entries.Where(static x => x.Level >= LogLevel.Warning).ToArray();
        Assert.That(warnings, Has.Length.EqualTo(1));
        Assert.That(warnings[0].Message, Does.Contain("rejected by the additional validation"));
        Assert.That(Counters.FailedDownloadEnds, Is.EqualTo(1));
        Assert.That(Counters.DownloadFailures, Is.EqualTo(new[] { FidoMetadataDownloadFailures.ChainRejected }));
    }

    private ChainValidatingFidoMetadataProvider CreateChainValidatingProvider(FakeLogger<DefaultFidoMetadataProvider> logger, bool acceptChain)
    {
        return new(
            Options,
            new DefaultSafeJsonSerializer(NullLogger<DefaultSafeJsonSerializer>.Instance),
            FakeFidoHttpClientProvider.Client,
            CreateTimeProvider(),
            Counters,
            logger,
            acceptChain);
    }

    private sealed class ChainValidatingFidoMetadataProvider : DefaultFidoMetadataProvider
    {
        private readonly bool _acceptChain;

        public ChainValidatingFidoMetadataProvider(
            IOptionsMonitor<WebAuthnOptions> options,
            ISafeJsonSerializer safeJsonSerializer,
            IFidoMetadataHttpClient metadataHttpClient,
            ITimeProvider timeProvider,
            IFidoMetadataCounters counters,
            ILogger<DefaultFidoMetadataProvider> logger,
            bool acceptChain)
            : base(options, safeJsonSerializer, metadataHttpClient, timeProvider, counters, logger)
        {
            _acceptChain = acceptChain;
        }

        public int ValidatedChainElements { get; private set; }

        public string ValidatedLeafThumbprint { get; private set; } = string.Empty;

        protected override Task<bool> ValidateJwtCertificateChainAsync(X509Chain chain, CancellationToken cancellationToken)
        {
            ValidatedChainElements = chain.ChainElements.Count;
            ValidatedLeafThumbprint = chain.ChainElements[0].Certificate.Thumbprint;
            return Task.FromResult(_acceptChain);
        }
    }
}
