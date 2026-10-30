using System;
using System.Buffers;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using WebAuthn.Net.Configuration.Options;

namespace WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataHttpClient;

/// <summary>
///     Default implementation of <see cref="IFidoMetadataHttpClient" />.
/// </summary>
/// <remarks>
///     The download is bounded to protect the application from a hostile or compromised endpoint. The response body is read as a stream
///     and the download is aborted as soon as the body exceeds <see cref="FidoMetadataOptions.MaxResponseSizeInBytes" /> (regardless of the 'Content-Length' header)
///     or the download takes longer than <see cref="FidoMetadataOptions.DownloadTimeout" /> (<see cref="System.Net.Http.HttpClient.Timeout" /> covers only the time
///     until the response headers are received, because the body is read as a stream).
/// </remarks>
public class DefaultFidoMetadataHttpClient : IFidoMetadataHttpClient
{
    /// <summary>
    ///     The size of the chunks in which the response body is read.
    /// </summary>
    protected const int ReadChunkSizeInBytes = 64 * 1024;

    /// <summary>
    ///     Constructs <see cref="DefaultFidoMetadataHttpClient" /> that doesn't report the aborted downloads to the log.
    /// </summary>
    /// <remarks>
    ///     The limits of the download are enforced, but their violations are reported only through the exceptions.
    ///     Use <see cref="DefaultFidoMetadataHttpClient(System.Net.Http.HttpClient, IOptionsMonitor{WebAuthnOptions}, ILogger{DefaultFidoMetadataHttpClient})" /> to log them.
    /// </remarks>
    /// <param name="httpClient">An HTTP client for downloading the blob with metadata.</param>
    /// <param name="options">Accessor for getting the current value of global options.</param>
    /// <exception cref="ArgumentNullException">Any of the parameters is <see langword="null" /></exception>
    public DefaultFidoMetadataHttpClient(
        HttpClient httpClient,
        IOptionsMonitor<WebAuthnOptions> options)
        : this(httpClient, options, NullLogger<DefaultFidoMetadataHttpClient>.Instance)
    {
    }

    /// <summary>
    ///     Constructs <see cref="DefaultFidoMetadataHttpClient" />
    /// </summary>
    /// <remarks>
    ///     The typed HttpClient factory of the dependency injection uses this constructor (see <see cref="ActivatorUtilitiesConstructorAttribute" />).
    /// </remarks>
    /// <param name="httpClient">An HTTP client for downloading the blob with metadata.</param>
    /// <param name="options">Accessor for getting the current value of global options.</param>
    /// <param name="logger">Logger.</param>
    /// <exception cref="ArgumentNullException">Any of the parameters is <see langword="null" /></exception>
    [ActivatorUtilitiesConstructor]
    public DefaultFidoMetadataHttpClient(
        HttpClient httpClient,
        IOptionsMonitor<WebAuthnOptions> options,
        ILogger<DefaultFidoMetadataHttpClient> logger)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(logger);
        HttpClient = httpClient;
        Options = options;
        Logger = logger;
    }

    /// <summary>
    ///     An HTTP client for downloading the blob with metadata.
    /// </summary>
    protected HttpClient HttpClient { get; }

    /// <summary>
    ///     Accessor for getting the current value of global options.
    /// </summary>
    protected IOptionsMonitor<WebAuthnOptions> Options { get; }

    /// <summary>
    ///     Logger.
    /// </summary>
    protected ILogger<DefaultFidoMetadataHttpClient> Logger { get; }

    /// <inheritdoc />
    /// <exception cref="HttpRequestException">The request failed, the response has an unsuccessful status code, or the response body exceeds <see cref="FidoMetadataOptions.MaxResponseSizeInBytes" />.</exception>
    /// <exception cref="TimeoutException">
    ///     The download wasn't completed within <see cref="FidoMetadataOptions.DownloadTimeout" />, or <see cref="System.Net.Http.HttpClient.Timeout" /> elapsed before the response headers were received.
    /// </exception>
    /// <exception cref="OperationCanceledException">The cancellation was requested through <paramref name="cancellationToken" />.</exception>
    public virtual async Task<string> DownloadMetadataAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var options = Options.CurrentValue.FidoMetadata;
        var maxResponseSizeInBytes = options.MaxResponseSizeInBytes;
        var downloadTimeout = options.DownloadTimeout;
        // The timeout covers the whole download, including the reading of the response body,
        // which HttpClient.Timeout doesn't limit when the response is read as a stream (HttpCompletionOption.ResponseHeadersRead).
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(downloadTimeout);
        try
        {
            using var response = await HttpClient.GetAsync(
                options.Mds3BlobUri,
                HttpCompletionOption.ResponseHeadersRead,
                timeoutCts.Token);
            response.EnsureSuccessStatusCode();
            var contentLength = response.Content.Headers.ContentLength;
            if (contentLength > maxResponseSizeInBytes)
            {
                // The declared size can't be trusted, but there is no point in reading a body that is declared to be too large.
                Logger.WarnDeclaredResponseSizeExceedsLimit(contentLength.Value, maxResponseSizeInBytes);
                throw new HttpRequestException($"The response of the FIDO Metadata Service declares a body of {contentLength.Value} bytes, which exceeds the maximum allowed size of {maxResponseSizeInBytes} bytes");
            }

            var stringResponse = await ReadContentAsync(response.Content, maxResponseSizeInBytes, timeoutCts.Token);
            // Not calling Trim can potentially break JWT validation.
            return stringResponse.Trim();
        }
        catch (OperationCanceledException exception) when (!cancellationToken.IsCancellationRequested)
        {
            // The caller hasn't requested the cancellation, so either the download timeout or HttpClient.Timeout has elapsed.
            Logger.WarnDownloadTimedOut(downloadTimeout, HttpClient.Timeout);
            throw new TimeoutException($"The download of the FIDO Metadata Service blob wasn't completed within the download timeout of {downloadTimeout} (or the HttpClient timeout of {HttpClient.Timeout} elapsed before the response headers were received)", exception);
        }
    }

    /// <summary>
    ///     Reads the response body as a string, aborting the reading as soon as the body exceeds the maximum size.
    /// </summary>
    /// <remarks>
    ///     The body is read in chunks and its size is checked after every chunk, so the limit is enforced even when the 'Content-Length' header is absent
    ///     or doesn't match the actual size of the body. The body is decoded as UTF-8 (the blob is a JWS in the compact serialization, which consists of ASCII characters),
    ///     honoring a byte order mark if present.
    /// </remarks>
    /// <param name="content">The content of the response.</param>
    /// <param name="maxResponseSizeInBytes">The maximum size of the body in bytes.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>The body of the response as a string.</returns>
    /// <exception cref="HttpRequestException">The body exceeds the maximum size.</exception>
    protected virtual async Task<string> ReadContentAsync(
        HttpContent content,
        long maxResponseSizeInBytes,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(content);
        await using var stream = await content.ReadAsStreamAsync(cancellationToken);
        // The capacity is not preallocated from 'Content-Length', because the declared size can't be trusted.
        using var body = new MemoryStream();
        var chunk = ArrayPool<byte>.Shared.Rent(ReadChunkSizeInBytes);
        try
        {
            long totalBytesRead = 0;
            int bytesRead;
            while ((bytesRead = await stream.ReadAsync(chunk.AsMemory(), cancellationToken)) > 0)
            {
                totalBytesRead += bytesRead;
                if (totalBytesRead > maxResponseSizeInBytes)
                {
                    Logger.WarnResponseSizeExceedsLimit(maxResponseSizeInBytes, content.Headers.ContentLength);
                    throw new HttpRequestException($"The response body of the FIDO Metadata Service exceeds the maximum allowed size of {maxResponseSizeInBytes} bytes");
                }

                await body.WriteAsync(chunk.AsMemory(0, bytesRead), cancellationToken);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(chunk);
        }

        body.Position = 0;
        using var reader = new StreamReader(body, Encoding.UTF8, true);
        return await reader.ReadToEndAsync(cancellationToken);
    }
}

/// <summary>
///     Extension methods for logging the download of the FIDO Metadata Service blob.
/// </summary>
public static partial class DefaultFidoMetadataHttpClientLoggingExtensions
{
    /// <summary>
    ///     The download of the FIDO Metadata Service blob was aborted because the response declares a body of {ContentLength} bytes, which exceeds the maximum allowed size of {MaxResponseSize} bytes
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="contentLength">The size of the body declared in the 'Content-Length' header of the response, in bytes.</param>
    /// <param name="maxResponseSize">The maximum allowed size of the body, in bytes.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The download of the FIDO Metadata Service blob was aborted because the response declares a body of {ContentLength} bytes, which exceeds the maximum allowed size of {MaxResponseSize} bytes")]
    public static partial void WarnDeclaredResponseSizeExceedsLimit(this ILogger logger, long contentLength, long maxResponseSize);

    /// <summary>
    ///     The download of the FIDO Metadata Service blob was aborted because the response body exceeds the maximum allowed size of {MaxResponseSize} bytes (the 'Content-Length' header of the response: {ContentLength})
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="maxResponseSize">The maximum allowed size of the body, in bytes.</param>
    /// <param name="contentLength">The size of the body declared in the 'Content-Length' header of the response, in bytes, or <see langword="null" /> if the header is absent.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The download of the FIDO Metadata Service blob was aborted because the response body exceeds the maximum allowed size of {MaxResponseSize} bytes (the 'Content-Length' header of the response: {ContentLength})")]
    public static partial void WarnResponseSizeExceedsLimit(this ILogger logger, long maxResponseSize, long? contentLength);

    /// <summary>
    ///     The download of the FIDO Metadata Service blob was aborted because it wasn't completed within the download timeout of {DownloadTimeout} (or the HttpClient timeout of {HttpClientTimeout} elapsed before the response headers were received)
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="downloadTimeout">The time limit for the whole download.</param>
    /// <param name="httpClientTimeout">The timeout of the HttpClient, which limits the time until the response headers are received.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The download of the FIDO Metadata Service blob was aborted because it wasn't completed within the download timeout of {DownloadTimeout} (or the HttpClient timeout of {HttpClientTimeout} elapsed before the response headers were received)")]
    public static partial void WarnDownloadTimedOut(this ILogger logger, TimeSpan downloadTimeout, TimeSpan httpClientTimeout);
}
