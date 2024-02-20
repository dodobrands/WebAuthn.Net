using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;
using WebAuthn.Net.Configuration.Options;

namespace WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataHttpClient;

/// <summary>
///     Default implementation of <see cref="IFidoMetadataHttpClient" />.
/// </summary>
public class DefaultFidoMetadataHttpClient : IFidoMetadataHttpClient
{
    /// <summary>
    ///     Constructs <see cref="DefaultFidoMetadataHttpClient" />
    /// </summary>
    /// <param name="httpClient">An HTTP client for downloading the blob with metadata.</param>
    /// <param name="options">Accessor for getting the current value of global options.</param>
    /// <exception cref="ArgumentNullException">Any of the parameters is <see langword="null" /></exception>
    public DefaultFidoMetadataHttpClient(
        HttpClient httpClient,
        IOptionsMonitor<WebAuthnOptions> options)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        ArgumentNullException.ThrowIfNull(options);
        HttpClient = httpClient;
        Options = options;
    }

    /// <summary>
    ///     An HTTP client for downloading the blob with metadata.
    /// </summary>
    protected HttpClient HttpClient { get; }

    /// <summary>
    ///     Accessor for getting the current value of global options.
    /// </summary>
    protected IOptionsMonitor<WebAuthnOptions> Options { get; }

    /// <inheritdoc />
    public virtual async Task<string> DownloadMetadataAsync(CancellationToken cancellationToken)
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
