using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataHttpClient;

namespace WebAuthn.Net.DSL.Fakes;

public class FakeFidoMetadataHttpClientProvider : IDisposable
{
    public FakeFidoMetadataHttpClientProvider(IEnumerable<KeyValuePair<string, string>>? configuration = null)
    {
        ConfigurationManager = new();
        ConfigurationManager.AddInMemoryCollection(configuration ?? Enumerable.Empty<KeyValuePair<string, string>>());
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

    private HttpClient HttpClient { get; }
    private FakeFidoMetadataDelegatingHandler FakeMetadataHandler { get; }
    private OptionsMonitor<DefaultFidoMetadataHttpClientOptions> Options { get; }
    private ConfigurationManager ConfigurationManager { get; }

    public DefaultFidoMetadataHttpClient Client { get; }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (disposing)
        {
            HttpClient.Dispose();
            FakeMetadataHandler.Dispose();
            Options.Dispose();
            ConfigurationManager.Dispose();
        }
    }
}
