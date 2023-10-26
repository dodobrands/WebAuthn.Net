using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;
using WebAuthn.Net.Configuration.Options;

namespace WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataHttpClient;

public class DefaultFidoMetadataHttpClient : IFidoMetadataHttpClient
{
    public DefaultFidoMetadataHttpClient(
        HttpClient httpClient,
        IOptionsMonitor<WebAuthnOptions> options)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        ArgumentNullException.ThrowIfNull(options);
        HttpClient = httpClient;
        Options = options;
    }

    protected HttpClient HttpClient { get; }
    protected IOptionsMonitor<WebAuthnOptions> Options { get; }

    public async Task<string> DownloadMetadataAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var response = await HttpClient.GetAsync(
            Options.CurrentValue.FidoMetadata.Mds3BlobUri,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken);
        response.EnsureSuccessStatusCode();
        var stringResponse = await response.Content.ReadAsStringAsync(cancellationToken);
        // Not calling Trim can potentially break JWT validation.
        return stringResponse.Trim();
    }
}
