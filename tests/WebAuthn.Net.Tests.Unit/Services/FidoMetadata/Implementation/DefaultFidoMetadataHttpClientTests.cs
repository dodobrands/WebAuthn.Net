using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using NUnit.Framework;
using WebAuthn.Net.DSL.Fakes;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataHttpClient;

namespace WebAuthn.Net.Services.FidoMetadata.Implementation;

public class DefaultFidoMetadataHttpClientTests
{
    private OptionsMonitor<DefaultFidoMetadataHttpClientOptions> Options { get; set; } = null!;
    private ConfigurationManager ConfigurationManager { get; set; } = null!;
    private DefaultFidoMetadataHttpClient Client { get; set; } = null!;
    private HttpClient HttpClient { get; set; } = null!;
    private FakeFidoMetadataDelegatingHandler FakeMetadataHandler { get; set; } = null!;

    [SetUp]
    public void SetupServices()
    {
        ConfigurationManager = new();
        ConfigurationManager.AddInMemoryCollection(GetConfiguration());
        var rawOptions = ConfigurationManager.Get<DefaultFidoMetadataHttpClientOptions>() ?? new DefaultFidoMetadataHttpClientOptions();
        var optionsCache = new OptionsCache<DefaultFidoMetadataHttpClientOptions>();
        optionsCache.TryAdd(string.Empty, rawOptions);
        Options = new(
            new OptionsFactory<DefaultFidoMetadataHttpClientOptions>(
                new List<IConfigureOptions<DefaultFidoMetadataHttpClientOptions>>(),
                new List<IPostConfigureOptions<DefaultFidoMetadataHttpClientOptions>>()),
            new List<IOptionsChangeTokenSource<DefaultFidoMetadataHttpClientOptions>>
            {
                new ConfigurationChangeTokenSource<DefaultFidoMetadataHttpClientOptions>(ConfigurationManager)
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

    protected virtual IEnumerable<KeyValuePair<string, string>> GetConfiguration()
    {
        yield break;
    }

    [Test]
    public async Task DefaultFidoMetadataHttpClient_DownloadMetadata_WhenSuccessfulResponse()
    {
        var result = await Client.DownloadMetadataAsync(CancellationToken.None);
        Assert.NotNull(result);
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
