using System;
using System.Collections.Generic;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NUnit.Framework;
using WebAuthn.Net.Configuration.Options;
using WebAuthn.Net.DSL.Fakes;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataProvider;
using WebAuthn.Net.Services.Serialization.Json.Implementation;

namespace WebAuthn.Net.Services.FidoMetadata.Implementation;

public class DefaultFidoMetadataProviderTests
{
    private OptionsMonitor<WebAuthnOptions> Options { get; set; } = null!;
    private ConfigurationManager ConfigurationManager { get; set; } = null!;
    private FakeFidoMetadataHttpClientProvider FakeFidoHttpClientProvider { get; set; } = null!;
    private DefaultFidoMetadataProvider MetadataProvider { get; set; } = null!;

    [SetUp]
    public void SetupServices()
    {
        ConfigurationManager = new();
        var webAuthnOptions = ConfigurationManager.Get<WebAuthnOptions>() ?? new WebAuthnOptions();
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
        MetadataProvider = new(
            Options,
            safeJsonDeserializer,
            FakeFidoHttpClientProvider.Client,
            new FakeTimeProvider(DateTimeOffset.Parse("2023-10-20T16:36:38Z", CultureInfo.InvariantCulture)));
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
    }
}
