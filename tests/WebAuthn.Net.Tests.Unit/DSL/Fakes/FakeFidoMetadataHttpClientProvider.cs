using System;
using System.Collections.Generic;
using System.Net.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using WebAuthn.Net.Configuration.Options;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataHttpClient;

namespace WebAuthn.Net.DSL.Fakes;

public class FakeFidoMetadataHttpClientProvider : IDisposable
{
    public FakeFidoMetadataHttpClientProvider()
    {
        ConfigurationManager = new();
        ConfigurationManager.AddInMemoryCollection([]);
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
        FakeMetadataHandler = new();
        HttpClient = new(FakeMetadataHandler, false);
        Client = new(HttpClient, Options);
    }

    private HttpClient HttpClient { get; }
    private FakeFidoMetadataDelegatingHandler FakeMetadataHandler { get; }
    private OptionsMonitor<WebAuthnOptions> Options { get; }
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
