using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using NUnit.Framework;
using WebAuthn.Net.Configuration.Options;
using WebAuthn.Net.DSL.Fakes;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataHttpClient;

namespace WebAuthn.Net.Services.FidoMetadata.Implementation;

public class DefaultFidoMetadataHttpClientTests
{
    private OptionsMonitor<WebAuthnOptions> Options { get; set; } = null!;
    private ConfigurationManager ConfigurationManager { get; set; } = null!;
    private DefaultFidoMetadataHttpClient Client { get; set; } = null!;
    private HttpClient HttpClient { get; set; } = null!;
    private FakeFidoMetadataDelegatingHandler FakeMetadataHandler { get; set; } = null!;

    [SetUp]
    public void SetupServices()
    {
        ConfigurationManager = new();
        ConfigurationManager.AddInMemoryCollection(GetConfiguration());
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
        FakeMetadataHandler = new();
        HttpClient = new(FakeMetadataHandler, false);
        Client = new(HttpClient, Options);
    }

    [TearDown]
    public virtual void TearDownServices()
    {
        HttpClient.Dispose();
        FakeMetadataHandler.Dispose();
        Options.Dispose();
        ConfigurationManager.Dispose();
    }

    [SuppressMessage("ReSharper", "ReturnTypeCanBeNotNullable")]
    protected virtual IEnumerable<KeyValuePair<string, string?>>? GetConfiguration()
    {
        yield break;
    }

    [Test]
    public async Task DefaultFidoMetadataHttpClient_DownloadMetadata_WhenSuccessfulResponse()
    {
        var result = await Client.DownloadMetadataAsync(CancellationToken.None);
        Assert.That(result, Is.Not.Null);
    }

    [Test]
    public void DefaultFidoMetadataHttpClient_DownloadMetadataThrows_When404Response()
    {
        FakeMetadataHandler.ReturnNotFound();
        Assert.ThrowsAsync<HttpRequestException>(async () =>
        {
            _ = await Client.DownloadMetadataAsync(CancellationToken.None);
        });
    }
}
